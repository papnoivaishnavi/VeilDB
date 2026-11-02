"""
Unit tests for the RBAC and Policy Engine module.

Tests role definitions, classification constants,
role-policy mappings, and policy lookups.
"""

import pytest
from backend.app.security.rbac import (
    Role,
    Classification,
    RBAC,
    get_masking_policy,
    can_access_full,
)
from backend.app.security.policies import PolicyEngine


class TestRoleEnum:
    """Tests for the Role enum."""

    def test_role_values(self):
        """Test that role enum has correct values."""
        assert Role.ADMIN.value == "ADMIN"
        assert Role.SUPPORT.value == "SUPPORT"
        assert Role.ANALYST.value == "ANALYST"
        assert Role.UNKNOWN.value == "UNKNOWN"

    def test_role_display_names(self):
        """Test display names for roles."""
        from backend.app.security.rbac import RBAC

        assert RBAC.get_role_display_name(Role.ADMIN) == "Administrator"
        assert RBAC.get_role_display_name(Role.SUPPORT) == "Support Staff"
        assert RBAC.get_role_display_name(Role.ANALYST) == "Analyst"
        assert RBAC.get_role_display_name(Role.UNKNOWN) == "Unknown Role"

    def test_get_role_known(self):
        """Test getting Role enum from known names."""
        assert RBAC.get_role("ADMIN") == Role.ADMIN
        assert RBAC.get_role("SUPPORT") == Role.SUPPORT
        assert RBAC.get_role("ANALYST") == Role.ANALYST

    def test_get_role_unknown(self):
        """Test getting Role enum from unknown name."""
        assert RBAC.get_role("INVALID") == Role.UNKNOWN


class TestClassificationEnum:
    """Tests for the Classification enum."""

    def test_classification_values(self):
        """Test that classification enum has correct values."""
        assert Classification.PII_HIGH.value == "PII_HIGH"
        assert Classification.PII_MEDIUM.value == "PII_MEDIUM"
        assert Classification.FINANCIAL_CONFIDENTIAL.value == "FINANCIAL_CONFIDENTIAL"
        assert Classification.NON_SENSITIVE.value == "NON_SENSITIVE"
        assert Classification.NEEDS_REVIEW.value == "NEEDS_REVIEW"


class TestRBACGetMaskingPolicy:
    """Tests for RBAC policy lookup."""

    def test_admin_policies(self):
        """ADMIN should have FULL access to all classifications."""
        # PII_HIGH
        policy = get_masking_policy("ADMIN", "PII_HIGH")
        assert policy == "FULL"

        # PII_MEDIUM
        policy = get_masking_policy("ADMIN", "PII_MEDIUM")
        assert policy == "FULL"

        # FINANCIAL_CONFIDENTIAL
        policy = get_masking_policy("ADMIN", "FINANCIAL_CONFIDENTIAL")
        assert policy == "FULL"

    def test_support_policies(self):
        """SUPPORT should have PARTIAL access to PII, FULL to financial."""
        # PII_HIGH
        policy = get_masking_policy("SUPPORT", "PII_HIGH")
        assert policy == "PARTIAL"

        # PII_MEDIUM
        policy = get_masking_policy("SUPPORT", "PII_MEDIUM")
        assert policy == "PARTIAL"

        # FINANCIAL_CONFIDENTIAL
        policy = get_masking_policy("SUPPORT", "FINANCIAL_CONFIDENTIAL")
        assert policy == "FULL"

    def test_analyst_policies(self):
        """ANALYST should have HASH for PII_HIGH, REDACT for others."""
        # PII_HIGH
        policy = get_masking_policy("ANALYST", "PII_HIGH")
        assert policy == "HASH"

        # PII_MEDIUM
        policy = get_masking_policy("ANALYST", "PII_MEDIUM")
        assert policy == "REDACT"

        # FINANCIAL_CONFIDENTIAL
        policy = get_masking_policy("ANALYST", "FINANCIAL_CONFIDENTIAL")
        assert policy == "REDACT"

    def test_unknown_role_raises(self):
        """Unknown roles should raise ValueError."""
        with pytest.raises(ValueError):
            get_masking_policy("INVALID_ROLE", "PII_HIGH")

    def test_unknown_classification(self):
        """Unknown classifications should be handled safely."""
        # This should raise ValueError for unknown classification combo
        with pytest.raises(ValueError):
            get_masking_policy("ADMIN", "UNKNOWN_CLASS")


class TestCanAccessFull:
    """Tests for can_access_full function."""

    def test_admin_can_access_full(self):
        """ADMIN should be able to access full values for all classifications."""
        assert can_access_full("ADMIN", "PII_HIGH") == True
        assert can_access_full("ADMIN", "PII_MEDIUM") == True
        assert can_access_full("ADMIN", "FINANCIAL_CONFIDENTIAL") == True

    def test_support_cannot_access_full_pii_high(self):
        """SUPPORT should NOT be able to access full PII_HIGH values."""
        assert can_access_full("SUPPORT", "PII_HIGH") == False

    def test_support_cannot_access_full_pii_medium(self):
        """SUPPORT should NOT be able to access full PII_MEDIUM values."""
        assert can_access_full("SUPPORT", "PII_MEDIUM") == False

    def test_support_can_access_full_financial(self):
        """SUPPORT should be able to access full FINANCIAL_CONFIDENTIAL values."""
        assert can_access_full("SUPPORT", "FINANCIAL_CONFIDENTIAL") == True

    def test_analyst_cannot_access_full(self):
        """ANALYST should NOT be able to access full values."""
        assert can_access_full("ANALYST", "PII_HIGH") == False
        assert can_access_full("ANALYST", "PII_MEDIUM") == False
        assert can_access_full("ANALYST", "FINANCIAL_CONFIDENTIAL") == False


class TestPolicyEngine:
    """Tests for the PolicyEngine class."""

    def test_policy_engine_default(self):
        """Test PolicyEngine with default policies."""
        engine = PolicyEngine()

        # ADMIN policies
        assert engine.get_masking_policy(Role.ADMIN, Classification.PII_HIGH) == "FULL"
        assert engine.get_masking_policy(Role.ADMIN, Classification.PII_MEDIUM) == "FULL"

        # SUPPORT policies
        assert engine.get_masking_policy(Role.SUPPORT, Classification.PII_HIGH) == "PARTIAL"
        assert engine.get_masking_policy(Role.SUPPORT, Classification.FINANCIAL_CONFIDENTIAL) == "FULL"

        # ANALYST policies
        assert engine.get_masking_policy(Role.ANALYST, Classification.PII_HIGH) == "HASH"
        assert engine.get_masking_policy(Role.ANALYST, Classification.PII_MEDIUM) == "REDACT"

    def test_policy_engine_custom(self):
        """Test PolicyEngine with custom policies."""
        from backend.app.security.rbac import Role
        from backend.app.security.policies import Classification

        custom_policies = {
            Role.ADMIN: {
                Classification.PII_HIGH: "PARTIAL",
                Classification.PII_MEDIUM: "PARTIAL",
                Classification.FINANCIAL_CONFIDENTIAL: "PARTIAL",
                Classification.NON_SENSITIVE: "FULL",
                Classification.NEEDS_REVIEW: "PARTIAL",
            },
        }
        engine = PolicyEngine(custom_policies=custom_policies)

        assert engine.get_masking_policy(Role.ADMIN, Classification.PII_HIGH) == "PARTIAL"
        assert engine.get_masking_policy(Role.ADMIN, Classification.FINANCIAL_CONFIDENTIAL) == "PARTIAL"

    def test_policy_engine_update(self):
        """Test updating policies at runtime."""
        from backend.app.security.rbac import Role
        from backend.app.security.policies import Classification

        engine = PolicyEngine()
        engine.update_policy(
            Role.ADMIN, Classification.PII_HIGH, "PARTIAL"
        )

        assert engine.get_masking_policy(Role.ADMIN, Classification.PII_HIGH) == "PARTIAL"

    def test_policy_engine_validate(self):
        """Test policy validation."""
        engine = PolicyEngine()

        # Valid policy should return True
        assert engine.validate_policy(Role.ADMIN, Classification.PII_HIGH) == True
        assert engine.validate_policy(Role.SUPPORT, Classification.PII_HIGH) == True

        # Invalid combination (unknown role) should return False
        assert engine.validate_policy(Role.UNKNOWN, Classification.PII_HIGH) == False


class TestPolicyEdgeCases:
    """Tests for policy edge cases."""

    def test_invalid_role_classification_combination(self):
        """Invalid role-classification combinations should be rejected."""
        from backend.app.security.rbac import Role, Classification

        # ADMIN with any classification should work
        for cls in [
            Classification.PII_HIGH,
            Classification.PII_MEDIUM,
            Classification.FINANCIAL_CONFIDENTIAL,
            Classification.NON_SENSITIVE,
            Classification.NEEDS_REVIEW,
        ]:
            policy = get_masking_policy("ADMIN", cls.value)
            assert policy == "FULL"

    def test_role_enum_vs_string(self):
        """Test that both Role enum and string work."""
        # String should work
        policy = get_masking_policy("ADMIN", "PII_HIGH")
        assert policy == "FULL"

        # Role enum should also work
        from backend.app.security.rbac import Role
        policy = get_masking_policy(Role.ADMIN, Classification.PII_HIGH)
        assert policy == "FULL"