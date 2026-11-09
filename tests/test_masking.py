"""
Unit tests for the Masking Engine module.

Tests all masking strategies: FULL, PARTIAL, REDACT, HASH.
Tests edge cases: NULL, empty strings, invalid input.
"""

import pytest
from backend.app.masking.strategies import (
    mask_value,
    FullMask,
    PartialMask,
    RedactMask,
    HMACMask,
    STRATEGY_REGISTRY,
    get_strategy,
)
from backend.app.masking.masking_engine import MaskingEngine


class TestMaskingStrategies:
    """Tests for individual masking strategies."""

    def test_full_mask_returns_original(self):
        """FULL strategy should return the original value."""
        strategy = FullMask()
        result = strategy.apply("4111111111111111")
        assert result == "4111111111111111"

        result = strategy.apply("john@example.com")
        assert result == "john@example.com"

        result = strategy.apply(None)
        assert result is None

    def test_partial_mask_credit_card(self):
        """PARTIAL strategy should mask credit cards."""
        strategy = PartialMask()
        result = strategy.apply("4111111111111111")
        assert result == "4111-XXXX-XXXX-1111"

        result = strategy.apply("5500000000000004")
        assert result == "5500-XXXX-XXXX-0004"

    def test_partial_mask_phone(self):
        """PARTIAL strategy should mask phone numbers."""
        strategy = PartialMask()
        result = strategy.apply("9876543210")
        # Should mask most digits, show last 4
        assert result == "*****3210"
        # Verify the format: 5 asterisks + 4 digits
        assert len(result) == 9
        assert result.startswith("*****")
        assert result[-4:].isdigit()

    def test_partial_mask_email(self):
        """PARTIAL strategy should mask email addresses."""
        strategy = PartialMask()
        result = strategy.apply("john@gmail.com")
        assert result == "j***@gmail.com"

        result = strategy.apply("a@gmail.com")
        # Even single-char local part should be preserved + ***
        assert result.startswith("a***")

    def test_partial_mask_generic(self):
        """PARTIAL strategy should mask generic values."""
        strategy = PartialMask()
        result = strategy.apply("very-long-value-that-should-be-masked")
        # Should show first and last 4 chars
        assert len(result) == len("very-long-value-that-should-be-masked")
        assert result[:4] == "very"
        # Last 4 chars should be the original last 4 chars
        assert result[-4:] == "sked"  # "masked" -> last 4 are "sked"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("ABCDE1234F", "******234F"),
            ("123-45-6789", "***-**-6789"),
            ("1990-05-15", "1990-**-**"),
            ("15/05/1990", "**/**/1990"),
            ("15-05-1990", "**-**-1990"),
            ("Aarav Mehta", "Aa*******ta"),
            ("Ravi Das", "Ra****as"),
            ("Li", "**"),
        ],
    )
    def test_partial_mask_hides_most_of_structured_values(self, value, expected):
        assert PartialMask().apply(value) == expected


class TestRedactMask:
    """Tests for the REDACT strategy."""

    def test_redact_mask(self):
        """REDACT strategy should replace with REDACTED."""
        strategy = RedactMask()
        result = strategy.apply("4111111111111111")
        assert result == "REDACTED"

        result = strategy.apply("john@gmail.com")
        assert result == "REDACTED"

        result = strategy.apply(None)
        assert result is None


class TestHMACMask:
    """Tests for the HMAC mask strategy."""

    def test_hmac_mask(self):
        """HASH strategy should produce deterministic HMAC-SHA256 hashes."""
        key = "test-secret-key"
        strategy = HMACMask(key=key)

        # Same input should produce same output
        result1 = strategy.apply("4111111111111111")
        result2 = strategy.apply("4111111111111111")
        assert result1 == result2

        # Different input should produce different output (with high probability)
        result3 = strategy.apply("9876543210")
        assert result1 != result3

        # Output should be hex string
        assert len(result1) == 64  # SHA-256 produces 256-bit = 64 hex chars

    def test_hmac_mask_with_salt(self):
        """HASH strategy should support salt in context."""
        strategy = HMACMask(key="test-secret")
        result1 = strategy.apply("value", {"salt": "salt1"})
        result2 = strategy.apply("value", {"salt": "salt2"})
        # Different salts should produce different hashes
        assert result1 != result2

        # Same salt should produce same hash
        result3 = strategy.apply("value", {"salt": "salt1"})
        assert result1 == result3


class TestMaskingEngine:
    """Tests for the MaskingEngine class."""

    def test_mask_value_with_strategy(self):
        """Test mask_value with explicit strategy."""
        engine = MaskingEngine()

        # FULL strategy returns original
        result = engine.mask_value(
            "4111111111111111", strategy="FULL"
        )
        assert result == "4111111111111111"

        # PARTIAL strategy masks credit card
        result = engine.mask_value(
            "4111111111111111", strategy="PARTIAL"
        )
        assert result == "4111-XXXX-XXXX-1111"

        # REDACT strategy
        result = engine.mask_value(
            "4111111111111111", strategy="REDACT"
        )
        assert result == "REDACTED"

        # HASH strategy
        result = engine.mask_value(
            "4111111111111111", strategy="HASH"
        )
        assert len(result) == 64  # SHA-256 hex digest

    def test_mask_value_with_role_and_classification(self):
        """Test mask_value with role and classification (via policy engine)."""
        from backend.app.security.rbac import Role
        from backend.app.security.policies import PolicyEngine

        engine = MaskingEngine(policy_engine=PolicyEngine())

        # ADMIN with PII_HIGH should get FULL access
        result = engine.mask_value(
            "4111111111111111",
            role="ADMIN",
            classification="PII_HIGH",
        )
        assert result == "4111111111111111"  # FULL = original

        # SUPPORT with PII_HIGH should get PARTIAL
        result = engine.mask_value(
            "4111111111111111",
            role="SUPPORT",
            classification="PII_HIGH",
        )
        assert result == "4111-XXXX-XXXX-1111"  # PARTIAL

        # ANALYST with PII_HIGH should get HASH
        result = engine.mask_value(
            "4111111111111111",
            role="ANALYST",
            classification="PII_HIGH",
        )
        assert len(result) == 64  # HASH

    def test_mask_value_null(self):
        """Test mask_value with None/NULL."""
        engine = MaskingEngine()

        result = engine.mask_value(None, strategy="PARTIAL")
        assert result is None

        result = engine.mask_value("", strategy="PARTIAL")
        assert result == ""

    def test_mask_value_unknown_strategy(self):
        """An unknown strategy must fail closed instead of exposing the value."""
        engine = MaskingEngine()

        result = engine.mask_value(
            "4111111111111111", strategy="UNKNOWN_STRATEGY"
        )
        assert result == "REDACTED"

    def test_mask_value_strategy_error_fails_closed(self, monkeypatch):
        """A strategy that raises must not leak the original value."""
        from backend.app.masking import strategies

        class BrokenMask(strategies.MaskingStrategy):
            def apply(self, value, context=None):
                raise RuntimeError("masking failed")

        monkeypatch.setitem(strategies.STRATEGY_REGISTRY, "BROKEN", BrokenMask())

        assert strategies.mask_value("4111111111111111", "BROKEN") == "REDACTED"

    def test_mask_engine_mask_column_value(self):
        """Test mask_column_value convenience method."""
        from backend.app.security.rbac import Role
        engine = MaskingEngine(policy_engine=None)

        # Without policy engine, ADMIN should get FULL
        result = engine.mask_column_value(
            "4111111111111111",
            column_classification="PII_HIGH",
            user_role="ADMIN",
        )
        assert result == "4111111111111111"  # ADMIN gets FULL

        result = engine.mask_column_value(
            "4111111111111111",
            column_classification="PII_HIGH",
            user_role="ANALYST",
        )
        assert len(result) == 64  # ANALYST gets HASH


class TestEdgeCases:
    """Tests for edge cases."""

    def test_mask_bool_values(self):
        """Boolean values should be handled safely."""
        from backend.app.masking.strategies import mask_value

        result = mask_value(True, strategy="PARTIAL")
        # Should not crash, handle safely
        assert result is not None

    def test_mask_float_values(self):
        """Float values should be handled."""
        from backend.app.masking.strategies import mask_value

        result = mask_value(3.14159, strategy="HASH")
        assert len(result) == 64

    def test_mask_integer_values(self):
        """Integer values should be handled."""
        from backend.app.masking.strategies import mask_value

        result = mask_value(12345, strategy="HASH")
        assert len(result) == 64

    def test_mask_datetime_values(self):
        """Datetime values should be handled."""
        from datetime import datetime
        from backend.app.masking.strategies import mask_value

        dt = datetime(2023, 1, 15, 10, 30, 0)
        result = mask_value(dt, strategy="HASH")
        assert len(result) == 64

    def test_mask_value_empty_string_context(self):
        """Test that empty strings are preserved."""
        from backend.app.masking.strategies import mask_value

        result = mask_value("", strategy="PARTIAL")
        assert result == ""


class TestStrategyRegistry:
    """Tests for the strategy registry."""

    def test_get_strategy(self):
        """Test getting strategies from registry."""
        # Should be able to get all standard strategies
        for strategy_name in ["FULL", "PARTIAL", "REDACT", "HASH"]:
            strategy = get_strategy(strategy_name)
            assert strategy is not None

    def test_get_strategy_unknown(self):
        """Test getting unknown strategy raises ValueError."""
        from backend.app.masking.strategies import get_strategy

        with pytest.raises(ValueError):
            get_strategy("STRATEGY_DOES_NOT_EXIST")
