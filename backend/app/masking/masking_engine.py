"""
Masking Engine Module.

Central engine for applying masking strategies to query result values.
Provides the mask_value function and integration with the RBAC policy engine.

This module is designed to be integrated into Member 2's query execution pipeline,
where values returned from database queries are transformed in memory before
being sent to the API response.
"""

from typing import Any, Dict, Optional, Union
from .strategies import (
    mask_value,
    FullMask,
    PartialMask,
    RedactMask,
    HMACMask,
    STRATEGY_REGISTRY,
    get_strategy,
)


class MaskingEngine:
    """Central engine for applying masking strategies to query result values."""

    def __init__(self, policy_engine=None):
        """Initialize the masking engine.

        Args:
            policy_engine: Optional RPolicies instance for role-based masking.
                If not provided, role-based default strategies are used.
        """
        self.policy_engine = policy_engine

    def mask_value(
        self,
        value: Any,
        strategy: Optional[str] = None,
        role: Optional[str] = None,
        classification: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Mask a value based on role, classification, and strategy.

        This is the main integration point. The masking behavior is determined
        by the combination of role and classification, with the strategy
        overridden if explicitly provided.

        Args:
            value: The value to mask. Can be string, int, float, date, or None.
            strategy: The masking strategy to use (FULL, PARTIAL, REDACT, HASH).
                If None, the policy-determined strategy is used.
            role: The user's role (ADMIN, SUPPORT, ANALYST).
            classification: The column's PII classification (PII_HIGH, PII_MEDIUM,
                FINANCIAL_CONFIDENTIAL, NON_SENSITIVE, NEEDS_REVIEW).
            context: Optional additional context (e.g., salt for hashing).

        Returns:
            The masked value appropriate for the user's role and the column's
            classification.
        """
        # If strategy is explicitly provided, use it
        if strategy is not None:
            return mask_value(value, strategy, context)

        # Otherwise, determine strategy via policy engine
        if self.policy_engine is not None:
            policy = self.policy_engine.get_masking_policy(role, classification)
            return mask_value(value, policy, context)

        # Fallback: use role-based default strategies when no policy engine
        if role is not None and classification is not None:
            role_defaults = {
                "ADMIN": "FULL",
                "SUPPORT": "PARTIAL",
                "ANALYST": "HASH",
            }
            default_strategy = role_defaults.get(role, "REDACT")
            return mask_value(value, default_strategy, context)

        # No role or classification info - return value unchanged
        return value

    def mask_column_value(
        self,
        value: Any,
        column_classification: str,
        user_role: str,
        strategy_override: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Mask a column value based on its classification and user role.

        This is a convenience method for the common case where you have the
        column's PII classification and the user's role.

        Args:
            value: The value to mask.
            column_classification: The column's classification (PII_HIGH, PII_MEDIUM,
                FINANCIAL_CONFIDENTIAL, etc.).
            user_role: The user's role (ADMIN, SUPPORT, ANALYST).
            strategy_override: Optional strategy to override the policy-determined one.
            context: Optional additional context.

        Returns:
            The masked value.
        """
        # Determine strategy from role and classification
        if strategy_override is not None:
            strategy = strategy_override
        elif self.policy_engine is not None:
            policy = self.policy_engine.get_masking_policy(user_role, column_classification)
            strategy = policy
        else:
            # Default fallback: use role-based strategies
            role_strategies = {
                "ADMIN": "FULL",
                "SUPPORT": "PARTIAL",
                "ANALYST": "HASH",
            }
            strategy = role_strategies.get(user_role, "REDACT")

        return mask_value(value, strategy, context)


# Provide a convenience instance
default_engine = MaskingEngine()