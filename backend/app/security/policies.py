"""
Policy Engine Module.

Implements configurable role-based policies for the Smart Data Masking System.

This module defines the role-policy mappings and provides the
get_masking_policy function used by the masking engine.

Policies are defined per role and per PII classification level.
Policy changes can be made by modifying the ROLE_POLICY_MAPPINGS
dict without rewriting the masking algorithms.
"""

from typing import Any, Dict, Optional
from .rbac import Role, Classification, RBAC, get_masking_policy as rbac_get_policy


# Official role-policy mappings (can be modified without changing code)
# These mappings define which masking strategy applies to each
# role-classification combination.

# ADMIN: Full access to everything
ADMIN_POLICIES: Dict[Classification, str] = {
    Classification.PII_HIGH: "FULL",
    Classification.PII_MEDIUM: "FULL",
    Classification.FINANCIAL_CONFIDENTIAL: "FULL",
    Classification.NON_SENSITIVE: "FULL",
    Classification.NEEDS_REVIEW: "FULL",
}

# SUPPORT: Partial access to PII, full access to financial data
SUPPORT_POLICIES: Dict[Classification, str] = {
    Classification.PII_HIGH: "PARTIAL",
    Classification.PII_MEDIUM: "PARTIAL",
    Classification.FINANCIAL_CONFIDENTIAL: "FULL",
    Classification.NON_SENSITIVE: "FULL",
    Classification.NEEDS_REVIEW: "PARTIAL",
}

# ANALYST: Hash for high PII, redaction for medium and financial
ANALYST_POLICIES: Dict[Classification, str] = {
    Classification.PII_HIGH: "HASH",
    Classification.PII_MEDIUM: "REDACT",
    Classification.FINANCIAL_CONFIDENTIAL: "REDACT",
    Classification.NON_SENSITIVE: "FULL",
    Classification.NEEDS_REVIEW: "REDACT",
}


class PolicyEngine:
    """Policy engine for role-based masking strategy lookup."""

    def __init__(self, custom_policies: Optional[Dict[Role, Dict[Classification, str]]] = None):
        """Initialize the policy engine.

        Args:
            custom_policies: Optional custom role-classification-policy mappings.
                If provided, these override the default mappings.
                Format: {Role: {Classification: strategy_name}}.
        """
        if custom_policies is not None:
            self._mappings = custom_policies
        else:
            # Use default mappings from RBAC module
            self._mappings = {
                Role.ADMIN: ADMIN_POLICIES,
                Role.SUPPORT: SUPPORT_POLICIES,
                Role.ANALYST: ANALYST_POLICIES,
            }

    def get_masking_policy(
        self,
        role: Role,
        classification: Classification,
    ) -> str:
        """Get the masking strategy for a given role and classification.

        Args:
            role: The user's role as a Role enum.
            classification: The column's classification as a Classification enum.

        Returns:
            The masking strategy name (FULL, PARTIAL, REDACT, HASH).

        Raises:
            ValueError: If the role is unknown or the classification is unknown,
                or the role-classification combination is not defined.
        """
        # Get the mappings for this role
        role_mappings = self._mappings.get(role)

        if role_mappings is None:
            # Unknown role - try the RBAC module fallback
            return rbac_get_policy(role, classification)

        # Get the policy for this classification
        policy = role_mappings.get(classification)

        if policy is None:
            # Unknown combination - safe default: reject
            raise ValueError(
                f"Undefined policy for role={role.value}, "
                f"classification={classification.value}. "
                "Access denied. Policy not configured."
            )

        return policy

    def update_policy(
        self,
        role: Role,
        classification: Classification,
        strategy: str,
    ) -> None:
        """Update a policy mapping without rewriting masking algorithms.

        This allows policy changes to be made at runtime without
        modifying the masking algorithm implementation.

        Args:
            role: The Role enum.
            classification: The Classification enum.
            strategy: The strategy name (FULL, PARTIAL, REDACT, HASH).

        Raises:
            ValueError: If the role or classification is unknown.
        """
        # Ensure the role exists in mappings
        if role not in self._mappings:
            raise ValueError(f"Unknown role: {role.value}")

        # Ensure the classification exists for this role
        if classification not in self._mappings[role]:
            # Add it if it's a valid classification
            valid_classifications = list(Classification)
            if classification not in valid_classifications:
                raise ValueError(
                    f"Unknown classification: {classification.value}. "
                    f"Valid: {[c.value for c in valid_classifications]}"
                )

        self._mappings[role][classification] = strategy

    def get_all_policies(self) -> Dict[str, Dict[str, str]]:
        """Get all role-classification-policy mappings as a nested dict.

        Returns:
            Dict mapping role names to classification-to-strategy dicts.
        """
        result = {}
        for role, mappings in self._mappings.items():
            result[role.value] = {c.value: s for c, s in mappings.items()}
        return result

    def validate_policy(self, role: Role, classification: Classification) -> bool:
        """Validate that a role-classification combination has a policy defined.

        Args:
            role: The Role enum.
            classification: The Classification enum.

        Returns:
            True if a policy is defined, False otherwise.
        """
        try:
            self.get_masking_policy(role, classification)
            return True
        except (ValueError, KeyError):
            return False