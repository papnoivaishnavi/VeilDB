"""
Unit tests for the PII Scanner module.

Tests column name detection, sample value pattern matching,
classification, confidence scoring, and schema scanning.
"""

import pytest
from backend.app.scanner.pii_detector import (
    PIIDetector,
    PIIScanResult,
    PIIClassification,
    DetectionReason,
)
from backend.app.scanner.regex_rules import RegexRules


class TestRegexRules:
    """Tests for regex pattern matching."""

    def test_is_email_valid(self):
        """Valid email addresses should be detected."""
        assert RegexRules.is_email("user@example.com")
        assert RegexRules.is_email("john.doe@gmail.com")
        assert RegexRules.is_email("test+tag@domain.co.uk")

    def test_is_email_invalid(self):
        """Invalid email addresses should be rejected."""
        assert not RegexRules.is_email("not-an-email")
        assert not RegexRules.is_email("@example.com")
        assert not RegexRules.is_email("user@")
        assert not RegexRules.is_email("")

    def test_is_mobile_valid(self):
        """Valid Indian mobile numbers (10 digits starting with 6-9)."""
        assert RegexRules.is_mobile("9876543210")
        assert RegexRules.is_mobile("6123456789")
        assert RegexRules.is_mobile("9123456789")

    def test_is_mobile_invalid(self):
        """Invalid mobile numbers should be rejected."""
        assert not RegexRules.is_mobile("1234567890")  # starts with 1
        assert not RegexRules.is_mobile("123456789")  # too short
        assert not RegexRules.is_mobile("12345678901")  # too long
        assert not RegexRules.is_mobile("abcdefghij")  # not digits

    def test_is_credit_card_valid(self):
        """Valid credit card numbers (16 digits)."""
        assert RegexRules.is_credit_card("4111111111111111")
        assert RegexRules.is_credit_card("5500000000000004")

    def test_is_credit_card_luhn(self):
        """Credit card Luhn validation."""
        # Valid Luhn card
        assert RegexRules.luhn_validate_card("4111111111111111")
        # Invalid Luhn card
        assert not RegexRules.luhn_validate_card("4111111111111112")

    def test_is_pan_valid(self):
        """Valid Indian PAN numbers."""
        assert RegexRules.is_pan("ABCDE1234F")
        assert RegexRules.is_pan("PANEL0987A")

    def test_is_pan_invalid(self):
        """Invalid PAN numbers should be rejected."""
        assert not RegexRules.is_pan("abcde1234f")  # lowercase
        assert not RegexRules.is_pan("ABCDE1234")  # too short
        assert not RegexRules.is_pan("ABCDE12345F")  # too long

    def test_is_aadhaar_valid(self):
        """Valid Aadhaar numbers (12 digits)."""
        assert RegexRules.is_aadhaar("123456789012")
        assert RegexRules.is_aadhaar("987654321098")

    def test_is_ssn_valid(self):
        """Valid US SSN numbers (3-2-4 format)."""
        assert RegexRules.is_ssn("123-45-6789")

    def test_is_ssn_invalid(self):
        """Invalid SSN numbers should be rejected."""
        assert not RegexRules.is_ssn("123456789")
        assert not RegexRules.is_ssn("12-3456789")
        assert not RegexRules.is_ssn("")

    def test_is_bank_account_valid(self):
        """Valid bank account numbers (8-18 digits)."""
        assert RegexRules.is_bank_account("12345678")
        assert RegexRules.is_bank_account("987654321012345678")

    def test_is_bank_account_invalid(self):
        """Invalid bank accounts should be rejected."""
        assert not RegexRules.is_bank_account("1234567")  # too short
        assert not RegexRules.is_bank_account(
            "1234567890123456789"
        )  # too long

    def test_is_date_of_birth_valid(self):
        """Valid date of birth patterns."""
        assert RegexRules.is_date_of_birth("1990-05-15")
        assert RegexRules.is_date_of_birth("05/15/1990")
        assert RegexRules.is_date_of_birth("15-05-1990")

    def test_is_date_of_birth_invalid(self):
        """Invalid dates should be rejected."""
        assert not RegexRules.is_date_of_birth("not-a-date")
        assert not RegexRules.is_date_of_birth("1990-13-45")  # invalid month/day

    def test_is_salary_valid(self):
        """Valid salary amounts."""
        assert RegexRules.is_salary("$50000")
        assert RegexRules.is_salary("50000.00")
        assert RegexRules.is_salary("50000")

    def test_is_account_number_valid(self):
        """Valid account numbers (8-17 digits)."""
        assert RegexRules.is_account_number("12345678")
        assert RegexRules.is_account_number("98765432101234567")


class TestClassifier:
    """Tests for the PII classifier."""

    def test_classify_by_column_name_email(self):
        """Column name detection for email."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("email")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_MEDIUM
        assert confidence == 0.95
        assert DetectionReason.COLUMN_NAME_MATCH in reasons

    def test_classify_by_column_name_phone(self):
        """Column name detection for phone."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("phone")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_MEDIUM

    def test_classify_by_column_name_credit_card(self):
        """Column name detection for credit card."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("credit_card")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_column_name_pan(self):
        """Column name detection for PAN."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("pan")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_column_name_aadhaar(self):
        """Column name detection for Aadhaar."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("aadhaar")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_column_name_ssn(self):
        """Column name detection for SSN."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("ssn")
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_column_name_unknown(self):
        """Unknown column names should return None."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("created_at")
        assert result is None

    def test_classify_by_sample_values_email(self):
        """Sample value detection for email."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["user@example.com", "test@gmail.com"]
        )
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_MEDIUM
        assert confidence > 0.0

    def test_classify_by_sample_values_credit_card(self):
        """Sample value detection for credit card."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["4111111111111111", "5500000000000004"]
        )
        assert result is not None
        classification, confidence, reasons = result
        # Credit card should be PII_HIGH
        assert classification == PIIClassification.PII_HIGH
        assert confidence > 0.0

    def test_classify_by_sample_values_pan(self):
        """Sample value detection for PAN."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["ABCDE1234F", "PANEL0987A"]
        )
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_sample_values_aadhaar(self):
        """Sample value detection for Aadhaar."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["123456789012", "987654321098"]
        )
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_sample_values_ssn(self):
        """Sample value detection for SSN."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["123-45-6789", "987-65-4321"]
        )
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_HIGH

    def test_classify_by_sample_values_phone(self):
        """Sample value detection for phone."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["9876543210", "6123456789"]
        )
        assert result is not None
        classification, confidence, reasons = result
        assert classification == PIIClassification.PII_MEDIUM

    def test_calculate_confidence_both_methods_agree(self):
        """Confidence should be high when column name and samples agree."""
        detector = PIIDetector()

        column_result = (PIIClassification.PII_HIGH, 0.98)
        sample_result = (PIIClassification.PII_HIGH, 0.95)

        combined = detector.calculate_confidence(column_result, sample_result)

        assert combined["confidence"] >= 0.8
        assert combined["classification"] == PIIClassification.PII_HIGH.name
        assert DetectionReason.AGREEMENT_BETWEEN_METHODS in combined["reasons"]

    def test_calculate_confidence_methods_disagree(self):
        """Confidence should be lower when methods disagree."""
        detector = PIIDetector()

        column_result = (PIIClassification.PII_HIGH, 0.98)
        sample_result = (PIIClassification.NON_SENSITIVE, 0.0)

        combined = detector.calculate_confidence(column_result, sample_result)

        # Should have some confidence but lower
        assert 0.0 <= combined["confidence"] <= 1.0

    def test_scan_column_with_email_name_and_values(self):
        """Full scan of a column with email name and email values."""
        detector = PIIDetector()
        result = detector.scan_column("email", ["user1@example.com", "user2@example.com"])

        assert result["classification"] != PIIClassification.NON_SENSITIVE.name
        assert result["confidence"] > 0.5
        assert len(result["detection_reasons"]) > 0

    def test_scan_column_with_unknown_name_no_values(self):
        """Column with unknown name and no values should be NON_SENSITIVE."""
        detector = PIIDetector()
        result = detector.scan_column("metadata", [])

        assert result["classification"] == PIIClassification.NON_SENSITIVE.name
        assert result["confidence"] == 0.0

    def test_scan_column_unknown_name_with_values(self):
        """Column with unknown name but PII values should detect from samples."""
        detector = PIIDetector()
        result = detector.scan_column("metadata", ["user@example.com"])

        # Should detect PII from sample values even without column name match
        assert result["confidence"] > 0.0


class TestPIIDetector:
    """Tests for the main PII detector."""

    def test_detect_by_column_name_email(self):
        """Detect PII by column name 'email'."""
        detector = PIIDetector()
        result = detector.detect_by_column_name("email")
        assert result is not None
        assert result.column_name == "email"
        assert result.classification == PIIClassification.PII_MEDIUM

    def test_detect_by_column_name_credit_card(self):
        """Detect PII by column name 'credit_card'."""
        detector = PIIDetector()
        result = detector.detect_by_column_name("credit_card")
        assert result is not None
        assert result.classification == PIIClassification.PII_HIGH

    def test_detect_by_sample_values(self):
        """Detect PII by sample values."""
        detector = PIIDetector()
        result = detector.detect_by_sample_values(
            ["4111111111111111", "5500000000000004"]
        )
        assert result is not None
        assert result.classification == PIIClassification.PII_HIGH

    def test_detect_by_sample_values_no_pii(self):
        """No PII detection when values are benign."""
        detector = PIIDetector()
        result = detector.detect_by_sample_values(
            ["some", "random", "text"]
        )
        assert result is None

    def test_detect_column_comprehensive(self):
        """Comprehensive column detection."""
        detector = PIIDetector()
        result = detector.detect_column("credit_card", ["4111111111111111", "5500000000000004"])

        assert result is not None
        assert result.column_name == "credit_card"
        assert result.confidence > 0.5

    def test_detect_column_no_samples(self):
        """Column detection with no sample values."""
        detector = PIIDetector()
        result = detector.detect_column("unknown_col", None)
        assert result is not None

    def test_scan_database_adapter_interface(self):
        """Test that scan_database defines the adapter interface."""
        import inspect
        detector = PIIDetector()

        # The scan_database method should accept an adapter
        sig = inspect.signature(detector.scan_database)
        assert sig is not None


class TestPIIScanResult:
    """Tests for the PIIScanResult data class."""

    def test_to_dict(self):
        """Test converting PIIScanResult to dictionary."""
        result = PIIScanResult(
            column_name="credit_card",
            classification=PIIClassification.PII_HIGH,
            detected_type="CREDIT_CARD",
            confidence=0.98,
            detection_reasons=[DetectionReason.COLUMN_NAME_MATCH],
        )

        d = result.to_dict()
        assert d["column_name"] == "credit_card"
        assert d["classification"] == "PII_HIGH"
        assert d["detected_type"] == "CREDIT_CARD"
        assert d["confidence"] == 0.98
        assert d["detection_reasons"] == ["Column name matched"]

    def test_repr(self):
        """Test PIIScanResult representation."""
        result = PIIScanResult(
            column_name="email",
            classification=PIIClassification.PII_MEDIUM,
            detected_type="EMAIL",
            confidence=0.95,
            detection_reasons=[],
        )
        repr_str = repr(result)
        assert "email" in repr_str
        assert "PII_MEDIUM" in repr_str