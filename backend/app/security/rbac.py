"""
Role-Based Access Control (RBAC) Module.

Implements role definitions, classification constants, and role-policy mappings
for the Smart Data Masking System.

Defines three roles with different masking permissions:
- ADMIN: Full access to all PII and financial data
- SUPPORT: Partial access to PII_HIGH and PII_MEDIUM, full access to FINANCIAL_CONFIDENTIAL
- ANALYST: Hash for PII_HIGH, redaction for PII_MEDIUM and FINANCIAL_CONFIDENTIAL
"""

from typing import Any, Dict, Optional, Tuple
from enum import Enum, auto


class Role(Enum):
    """Enumeration of user roles in the system."""

    ADMIN = "ADMIN"
    SUPPORT = "SUPPORT"
    ANALYST = "ANALYST"
    UNKNOWN = "UNKNOWN"


class Classification(Enum):
    """Enumeration of PII classification levels."""

    PII_HIGH = "PII_HIGH"
    PII_MEDIUM = "PII_MEDIUM"
    FINANCIAL_CONFIDENTIAL = "FINANCIAL_CONFIDENTIAL"
    NON_SENSITIVE = "NON_SENSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


# Role-policy mappings: role -> {classification -> strategy}
ROLE_POLICY_MAPPINGS: Dict[Role, Dict[Classification, str]] = {
    Role.ADMIN: {
        Classification.PII_HIGH: "FULL",
        Classification.PII_MEDIUM: "FULL",
        Classification.FINANCIAL_CONFIDENTIAL: "FULL",
        Classification.NON_SENSITIVE: "FULL",
        Classification.NEEDS_REVIEW: "FULL",
    },
    Role.SUPPORT: {
        Classification.PII_HIGH: "PARTIAL",
        Classification.PII_MEDIUM: "PARTIAL",
        Classification.FINANCIAL_CONFIDENTIAL: "FULL",
        Classification.NON_SENSITIVE: "FULL",
        Classification.NEEDS_REVIEW: "PARTIAL",
    },
    Role.ANALYST: {
        Classification.PII_HIGH: "HASH",
        Classification.PII_MEDIUM: "REDACT",
        Classification.FINANCIAL_CONFIDENTIAL: "REDACT",
        Classification.NON_SENSITIVE: "FULL",
        Classification.NEEDS_REVIEW: "REDACT",
    },
}


class RBAC:
    """Role-Based Access Control implementation."""

    @staticmethod
    def get_role(role_name: str) -> Role:
        """Convert a role name string to a Role enum.

        Args:
            role_name: The role name as a string or Role enum.

        Returns:
            The corresponding Role enum value, or Role.UNKNOWN if not recognized.
        """
        # Handle if already a Role enum
        if isinstance(role_name, Role):
            return role_name

        role_map = {
            Role.ADMIN.value: Role.ADMIN,
            Role.SUPPORT.value: Role.SUPPORT,
            Role.ANALYST.value: Role.ANALYST,
        }
        return role_map.get(role_name, Role.UNKNOWN)

    @staticmethod
    def get_classification(class_name: str) -> Classification:
        """Convert a classification name string to a Classification enum.

        Args:
            class_name: The classification name as a string or Classification enum.

        Returns:
            The corresponding Classification enum value.

        Raises:
            ValueError: If the classification name is not recognized.
        """
        # Handle if already a Classification enum
        if isinstance(class_name, Classification):
            return class_name

        class_map = {
            Classification.PII_HIGH.value: Classification.PII_HIGH,
            Classification.PII_MEDIUM.value: Classification.PII_MEDIUM,
            Classification.FINANCIAL_CONFIDENTIAL.value: Classification.FINANCIAL_CONFIDENTIAL,
            Classification.NON_SENSITIVE.value: Classification.NON_SENSITIVE,
            Classification.NEEDS_REVIEW.value: Classification.NEEDS_REVIEW,
        }
        result = class_map.get(class_name)
        if result is None:
            raise ValueError(f"Unknown classification: {class_name}")
        return result

    @staticmethod
    def get_masking_policy(role: Role, classification: Classification) -> str:
        """Get the masking strategy for a given role and classification.

        Args:
            role: The user's role.
            classification: The column's PII classification.

        Returns:
            The masking strategy name (FULL, PARTIAL, REDACT, HASH).

        Raises:
            ValueError: If the role is unknown or the classification is unknown.
        """
        # Check for unknown role
        if role == Role.UNKNOWN:
            raise ValueError(
                f"Unknown role: {role.value}. "
                "Access denied. Default: reject unknown roles."
            )

        # Check for unknown classification
        if classification == Classification.NON_SENSITIVE and role != Role.ADMIN:
            # Non-sensitive is safe, but let's be explicit
            pass

        # Try to get the policy from the mappings
        try:
            policy = ROLE_POLICY_MAPPINGS[role][classification]
            return policy
        except KeyError:
            # Unknown combination - safe default: reject, don't default to FULL
            raise ValueError(
                f"Unknown role-classification combination: "
                f"role={role.value}, classification={classification.value}. "
                "Access denied. Policy lookup failed."
            )

        # Should not reach here, but just in case
        return "REDACT"

    @staticmethod
    def can_access_full(role: Role, classification: Classification) -> bool:
        """Check if a role can access full (unmasked) values.

        Args:
            role: The user's role.
            classification: The column's PII classification.

        Returns:
            True if the role can access full values, False otherwise.
        """
        try:
            policy = RBAC.get_masking_policy(role, classification)
            return policy == "FULL"
        except ValueError:
            # Unknown role or classification - deny by default
            return False

    @staticmethod
    def get_role_display_name(role: Role) -> str:
        """Get the display name for a role.

        Args:
            role: The Role enum.

        Returns:
            Human-readable role name.
        """
        names = {
            Role.ADMIN: "Administrator",
            Role.SUPPORT: "Support Staff",
            Role.ANALYST: "Analyst",
            Role.UNKNOWN: "Unknown Role",
        }
        return names.get(role, "Unknown")


# Provide convenience functions for direct use


def get_masking_policy(role: str, classification: str) -> str:
    """Get the masking strategy for a given role and classification.

    Convenience function that converts string role/classification to enums
    and looks up the policy.

    Args:
        role: The user's role as a string (ADMIN, SUPPORT, ANALYST).
        classification: The column's classification as a string (PII_HIGH, PII_MEDIUM,
            FINANCIAL_CONFIDENTIAL, NON_SENSITIVE, NEEDS_REVIEW).

    Returns:
        The masking strategy name (FULL, PARTIAL, REDACT, HASH).

    Raises:
        ValueError: If the role or classification is unknown.
    """
    role_enum = RBAC.get_role(role)
    classification_enum = RBAC.get_classification(classification)

    # Reject unknown roles
    if role_enum == Role.UNKNOWN:
        raise ValueError(f"Unknown role: {role}. Access denied.")

    return RBAC.get_masking_policy(role_enum, classification_enum)


def can_access_full(role: str, classification: str) -> bool:
    """Check if a role can access full (unmasked) values.

    Args:
        role: The user's role as a string.
        classification: The column's classification as a string.

    Returns:
        True if the role can access full values, False otherwise.
    """
    role_enum = RBAC.get_role(role)
    classification_enum = RBAC.get_classification(classification)

    if role_enum == Role.UNKNOWN:
        return False

    return RBAC.can_access_full(role_enum, classification_enum)