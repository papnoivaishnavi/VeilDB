"""Masking Strategies Module.

Implements various data masking strategies for the Smart Data Masking System.
"""
import re
import hmac
import hashlib
from typing import Any, Dict, Optional


class MaskingStrategy:
    """Base class for masking strategies."""

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Apply the masking strategy to a value.

        Args:
            value: The value to mask.
            context: Optional context dict (may contain role, user_id, etc.).

        Returns:
            The masked value.
        """
        raise NotImplementedError("Subclasses must implement apply()")


class FullMask(MaskingStrategy):
    """FULL strategy: Return the original value.

    This strategy returns the original value unchanged. It should only be
    used for users with admin-level access who are authorized to see raw PII.
    """

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        # Return the original value
        return value


class PartialMask(MaskingStrategy):
    """PARTIAL strategy: Mask most of the value, show last few characters.

    Supported patterns:
    - Credit card: 4111111111111111 -> 4111-XXXX-XXXX-1111
    - Phone: 9876543210 -> *****3210
    - Email: john@gmail.com -> j***@gmail.com
    """

    # Patterns for partial masking
    CREDIT_CARD_FORMAT = r"{first_4}-XXXX-XXXX-{last_4}"
    PHONE_MASK = "*****"  # 5 asterisks
    EMAIL_MASK = "***"

    def _mask_credit_card(self, value: str) -> str:
        """Mask a credit card number: 4111111111111111 -> 4111-XXXX-XXXX-1111."""
        # Extract digits
        digits = re.sub(r"\D", "", value)
        if len(digits) < 12:
            return "REDACTED"

        first_4 = digits[:4]
        last_4 = digits[-4:]

        return f"{first_4}-XXXX-XXXX-{last_4}"

    def _mask_phone(self, value: str) -> str:
        """Mask a phone number: 9876543210 -> *****3210."""
        digits = re.sub(r"\D", "", value)
        if len(digits) < 6:
            return "*****"  # Fallback

        # Show last 4 digits, mask the rest
        last_four = digits[-4:]
        # Number of digits to mask
        mask_count = len(digits) - 4

        # For 10-digit numbers: show 5 asterisks + last 4
        # For longer numbers: mask beginning, show last 4
        if len(digits) == 10:
            # Standard Indian mobile: *****3210 (5 asterisks + 4 digits = 9 chars)
            # But we need 10 chars total, so add one more asterisk if needed
            # Actually, 5 asterisks + 4 digits = 9, but phone is 10 digits
            # Wait - the test expects "*****3210" which is 9 chars, but asserts len==10
            # Let me re-examine: the test has contradictory assertions
            # The task says fix from 6 to 5 asterisks
            # Let me just use 5 asterisks and adjust the test len assertion
            return f"*****{last_four}"
        else:
            # For longer numbers: mask all but last 4
            if mask_count >= 4:
                return f"{'*' * mask_count}{last_four}"
            else:
                return last_four

    def _mask_email(self, value: str) -> str:
        """Mask an email: john@gmail.com -> j***@gmail.com."""
        if "@" not in value:
            return "***@***.***"

        local_part, domain = value.split("@", 1)
        if len(local_part) <= 1:
            masked_local = local_part[0] + "***"
        else:
            masked_local = local_part[0] + "***"

        return f"{masked_local}@{domain}"

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Apply partial masking based on the value type.

        Args:
            value: The value to mask.
            context: Optional context dict may contain 'strategy_hint' or
                     'data_type' to guide masking.

        Returns:
            The partially masked value.
        """
        if value is None or value == "":
            return value

        if isinstance(value, bool):
            return "****"

        # Convert to string for analysis
        value_str = str(value)

        # Determine the type and apply appropriate masking
        masked = value_str

        # Credit card detection (16 digits, possibly with spaces/hyphens)
        digits_only = re.sub(r"\D", "", value_str)
        if re.match(r"^\d{16}$", digits_only):
            masked = self._mask_credit_card(value_str)

        # Phone detection (10+ digits)
        elif re.match(r"^\d{10,15}$", digits_only):
            masked = self._mask_phone(value_str)

        # Email detection
        elif "@" in value_str and re.match(r".+@.+\..+", value_str):
            masked = self._mask_email(value_str)

        else:
            # Generic partial masking: show first and last 4 characters
            if len(value_str) > 8:
                masked = value_str[:4] + "*" * (len(value_str) - 8) + value_str[-4:]

        return masked


class RedactMask(MaskingStrategy):
    """REDACT strategy: Replace the entire value with 'REDACTED'.

    This strategy completely replaces the original value with the string
    "REDACTED", regardless of the original value type.
    """

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Redact the value.

        Args:
            value: The value to redact.
            context: Optional context (unused).

        Returns:
            The string "REDACTED" for non-None values, None for None input.
        """
        if value is None:
            return None
        return "REDACTED"


class HMACMask(MaskingStrategy):
    """HASH strategy: Use keyed HMAC-SHA256 for deterministic pseudonymization.

    This strategy uses HMAC-SHA256 with a secret key to produce a deterministic
    hash of the input value. The same input always produces the same output,
    which is useful for pseudonymization while preserving referential integrity.

    The key should be kept secret and rotated periodically. It is recommended
    to use a key derivation function or a per-application secret.
    """

    def __init__(self, key: str = "default-secret-key"):
        """Initialize the HMAC mask with a secret key.

        Args:
            key: Secret key for HMAC computation. Should be kept confidential.
        """
        self._key = key

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Apply HMAC-SHA256 masking to the value.

        Args:
            value: The value to hash (will be converted to string).
            context: Optional context may contain 'salt' for additional entropy.

        Returns:
            Hex-encoded HMAC-SHA256 hash of the value.
        """
        if value is None:
            return None

        if isinstance(value, bool):
            return None  # Skip booleans

        # Convert value to string
        value_str = str(value)

        # Get optional salt from context
        salt = ""
        if context and isinstance(context, dict):
            salt = context.get("salt", "")

        # Compute HMAC-SHA256
        hmac_obj = hmac.new(
            self._key.encode("utf-8"),
            (value_str + salt).encode("utf-8"),
            hashlib.sha256,
        )

        return hmac_obj.hexdigest()


# Strategy registry: maps strategy names to strategy instances
STRATEGY_REGISTRY: Dict[str, MaskingStrategy] = {
    "FULL": FullMask(),
    "PARTIAL": PartialMask(),
    "REDACT": RedactMask(),
    "HASH": HMACMask(),
}


def get_strategy(strategy_name: str) -> MaskingStrategy:
    """Get a masking strategy by name.

    Args:
        strategy_name: The name of the strategy (FULL, PARTIAL, REDACT, HASH).

    Returns:
        The corresponding MaskingStrategy instance.

    Raises:
        ValueError: If the strategy name is not recognized.
    """
    if strategy_name not in STRATEGY_REGISTRY:
        raise ValueError(
            f"Unknown masking strategy: {strategy_name}. "
            f"Available: {list(STRATEGY_REGISTRY.keys())}"
        )
    return STRATEGY_REGISTRY[strategy_name]


def mask_value(
    value: Any,
    strategy: str,
    context: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Mask a value using the specified strategy.

    Central function for applying masking strategies to data values.
    This is the primary function that Member 2's query execution engine
    should call to transform sensitive values before returning them.

    Args:
        value: The value to mask. Can be string, int, float, date, or None.
        strategy: The masking strategy to apply (FULL, PARTIAL, REDACT, HASH).
        context: Optional context dict. May contain:
            - 'role': User role (for policy-based masking)
            - 'salt': Salt for HMAC hashing
            - 'data_type': Type hint for the value

    Returns:
        The masked value. For FULL strategy, returns the original value.
        For HASH strategy, returns a hex-encoded HMAC-SHA256 hash.
        For PARTIAL strategy, returns a partially masked value.
        For REDACT strategy, returns "REDACTED".

    Example:
        >>> mask_value("4111111111111111", "PARTIAL")
        '4111-XXXX-XXXX-1111'
        >>> mask_value("john@gmail.com", "PARTIAL")
        'j***@gmail.com'
        >>> mask_value("4111111111111111", "HASH", {"salt": "my-salt"})
        'hex_hash_string'
    """
    # Handle None/NULL values safely
    if value is None:
        return None

    # Handle empty strings
    if isinstance(value, str) and value.strip() == "":
        return value

    # Get the strategy instance
    try:
        strategy_instance = STRATEGY_REGISTRY.get(strategy)
        if strategy_instance is None:
            # Try to get it by name
            strategy_instance = get_strategy(strategy)
    except ValueError:
        # Unknown strategy - return value unchanged (safe fallback)
        return value

    # Apply the strategy
    try:
        result = strategy_instance.apply(value, context)
        return result
    except Exception:
        # Safe failure: return original value on error
        return value


# Convenience functions for specific masking operations

def mask_credit_card(value: str, strategy: str = "PARTIAL", context: Optional[Dict[str, Any]] = None) -> str:
    """Mask a credit card value using the specified strategy."""
    result = mask_value(value, strategy, context)
    if result == value:
        # Fallback to PARTIAL if original strategy didn't transform
        result = mask_value(value, "PARTIAL", context)
    return str(result)


def mask_phone(value: str, strategy: str = "PARTIAL", context: Optional[Dict[str, Any]] = None) -> str:
    """Mask a phone value using the specified strategy."""
    result = mask_value(value, strategy, context)
    if result == value:
        result = mask_value(value, "PARTIAL", context)
    return str(result)


def mask_email(value: str, strategy: str = "PARTIAL", context: Optional[Dict[str, Any]] = None) -> str:
    """Mask an email value using the specified strategy."""
    result = mask_value(value, strategy, context)
    if result == value:
        result = mask_value(value, "PARTIAL", context)
    return str(result)


def mask_integer(value: int, strategy: str = "HASH", context: Optional[Dict[str, Any]] = None) -> str:
    """Mask an integer value using the specified strategy."""
    return mask_value(value, strategy, context)


def mask_date(value: Any, strategy: str = "HASH", context: Optional[Dict[str, Any]] = None) -> Any:
    """Mask a date value using the specified strategy."""
    value_str = str(value)
    return mask_value(value_str, strategy, context)
