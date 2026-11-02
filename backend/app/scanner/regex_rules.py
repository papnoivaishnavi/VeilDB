"""
Regex-based PII detection rules.

This module implements regular expression patterns for detecting personally
identifiable information (PII) in database column sample values.

Supported patterns:
- Email addresses
- Indian mobile numbers (starting with 6-9)
- Credit card numbers (with Luhn validation)
- Indian PAN numbers
- Aadhaar numbers (12-digit)
- US Social Security Numbers
- Bank account identifiers
- Date of birth patterns
"""

import re
from datetime import date as _date
from typing import Optional, Dict, List, Any


class RegexRules:
    """Regular expression patterns for PII detection."""

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    # Indian mobile number pattern (10 digits, starting with 6-9)
    MOBILE_PATTERN = re.compile(r"^[6-9]\d{9}$")

    # Credit card number pattern (16 digits, possibly with spaces/hyphens)
    CREDIT_CARD_PATTERN = re.compile(r"^\d{16}$")

    # Indian PAN number pattern (5 uppercase letters + 4 digits + 1 uppercase letter)
    PAN_PATTERN = re.compile(r"^[A-Z]{5}\d{4}[A-Z]{1}$")

    # Aadhaar number pattern (12 digits)
    AADHAAR_PATTERN = re.compile(r"^\d{12}$")

    # US SSN pattern (3-2-4 digits)
    SSN_PATTERN = re.compile(r"^\d{3}-\d{2}-\d{4}$")

    # Bank account pattern (8-18 digits)
    BANK_ACCOUNT_PATTERN = re.compile(r"^\d{8,18}$")

    # Date of birth patterns
    DATE_PATTERN = re.compile(
        r"^\d{4}-\d{2}-\d{2}$|^\d{2}/\d{2}/\d{4}$|^\d{2}-\d{2}-\d{4}$"
    )

    # Salary pattern (currency amount)
    SALARY_PATTERN = re.compile(r"^\$?\d+(?:\.\d{1,2})?$")

    # Account number pattern
    ACCOUNT_NUMBER_PATTERN = re.compile(r"^\d{8,17}$")

    # Luhn validation for credit cards
    @staticmethod
    def luhn_checksum(card_number: str) -> bool:
        """
        Validate a credit card number using the Luhn algorithm.

        The Luhn algorithm (also known as modulus 10 or MOD 10) is a simple
        checksum formula used to validate a variety of identification numbers,
        especially credit card numbers.

        Args:
            card_number: The credit card number as a string (digits only).

        Returns:
            True if the card number is valid according to Luhn, False otherwise.
        """
        if not card_number or not card_number.isdigit():
            return False

        digits = [int(d) for d in card_number]
        odd_sum = sum(digits[-1::-2])  # sum of odd-positioned digits from right
        even_sum = 0
        for d in digits[-2::-2]:  # even-positioned digits, doubled
            doubled = d * 2
            even_sum += doubled - 9 if doubled > 9 else doubled

        return (odd_sum + even_sum) % 10 == 0

    @staticmethod
    def luhn_validate_card(value: str) -> bool:
        """Validate a credit card number with Luhn checksum."""
        cleaned = re.sub(r"\D", "", value)
        if len(cleaned) < 13 or len(cleaned) > 19:
            return False
        return RegexRules.luhn_checksum(cleaned)

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    # Indian mobile number pattern (10 digits, starting with 6-9)
    MOBILE_PATTERN = re.compile(r"^[6-9]\d{9}$")

    # Credit card number pattern (16 digits, possibly with spaces/hyphens)
    CREDIT_CARD_PATTERN = re.compile(r"^\d{16}$")

    # Indian PAN number pattern (5 uppercase letters + 4 digits + 1 uppercase letter)
    PAN_PATTERN = re.compile(r"^[A-Z]{5}\d{4}[A-Z]{1}$")

    # Aadhaar number pattern (12 digits)
    AADHAAR_PATTERN = re.compile(r"^\d{12}$")

    # US SSN pattern (3-2-4 digits)
    SSN_PATTERN = re.compile(r"^\d{3}-\d{2}-\d{4}$")

    # Bank account pattern (8-18 digits)
    BANK_ACCOUNT_PATTERN = re.compile(r"^\d{8,18}$")

    # Date of birth patterns
    DATE_PATTERN = re.compile(
        r"^\d{4}-\d{2}-\d{2}$|^\d{2}/\d{2}/\d{4}$|^\d{2}-\d{2}-\d{4}$"
    )

    # Salary pattern (currency amount)
    SALARY_PATTERN = re.compile(r"^\$?\d+(?:\.\d{1,2})?$")

    # Account number pattern
    ACCOUNT_NUMBER_PATTERN = re.compile(r"^\d{8,17}$")

    @staticmethod
    def is_email(value: str) -> bool:
        """Check if a value matches an email address pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.EMAIL_PATTERN.match(value))

    @staticmethod
    def is_mobile(value: str) -> bool:
        """Check if a value matches an Indian mobile number pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.MOBILE_PATTERN.match(value))

    @staticmethod
    def is_credit_card(value: str) -> bool:
        """Check if a value matches a credit card number pattern."""
        if not isinstance(value, str):
            return False
        # Remove spaces and hyphens for matching
        cleaned = re.sub(r"[\s-]", "", value)
        return bool(RegexRules.CREDIT_CARD_PATTERN.match(cleaned))

    @staticmethod
    def is_pan(value: str) -> bool:
        """Check if a value matches an Indian PAN number pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.PAN_PATTERN.match(value))

    @staticmethod
    def is_aadhaar(value: str) -> bool:
        """Check if a value matches an Aadhaar number pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.AADHAAR_PATTERN.match(value))

    @staticmethod
    def is_ssn(value: str) -> bool:
        """Check if a value matches a US SSN pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.SSN_PATTERN.match(value))

    @staticmethod
    def is_bank_account(value: str) -> bool:
        """Check if a value matches a bank account pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.BANK_ACCOUNT_PATTERN.match(value))

    @staticmethod
    def is_date_of_birth(value: str) -> bool:
        """Check if a value matches a date of birth pattern.

        Validates that the date is actually valid (rejects invalid months
        like 13, days like 45, etc.) for all three supported formats:
        YYYY-MM-DD, MM/DD/YYYY, DD-MM-YYYY.
        """
        if not isinstance(value, str):
            return False

        # Try YYYY-MM-DD format
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", value)
        if m:
            year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        else:
            # Try MM/DD/YYYY format
            m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", value)
            if m:
                month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
            else:
                # Must be DD-MM-YYYY format (already matched by DATE_PATTERN)
                m = re.match(r"^(\d{2})-(\d{2})-(\d{4})$", value)
                if m:
                    day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
                else:
                    return False

        try:
            _date(year, month, day)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_salary(value: str) -> bool:
        """Check if a value matches a salary pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.SALARY_PATTERN.match(value))

    @staticmethod
    def is_account_number(value: str) -> bool:
        """Check if a value matches an account number pattern."""
        if not isinstance(value, str):
            return False
        return bool(RegexRules.ACCOUNT_NUMBER_PATTERN.match(value))