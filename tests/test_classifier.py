"""
Unit tests for the PII Classification module.

Tests classification levels, confidence scoring, and detection reasons.
"""

import pytest
from backend.app.scanner.classifier import (
    PIIClassification,
    PIIDetector,
    DetectionReason,
)
from backend.app.scanner.regex_rules import RegexRules


class TestPIIClassification:
    """Tests for the PIIClassification enum."""

    def test_classification_enum_values(self):
        """Test all classification enum values exist."""
        assert PIIClassification.PII_HIGH.name == "PII_HIGH"
        assert PIIClassification.PII_MEDIUM.name == "PII_MEDIUM"
        assert PIIClassification.FINANCIAL_CONFIDENTIAL.name == "FINANCIAL_CONFIDENTIAL"
        assert PIIClassification.NON_SENSITIVE.name == "NON_SENSITIVE"
        assert PIIClassification.NEEDS_REVIEW.name == "NEEDS_REVIEW"

    def test_classification_enum_values_str(self):
        """Test classification enum string values."""
        # Note: PIIClassification uses auto(), so .value gives integers
        # This test verifies the string representation
        assert PIIClassification.PII_HIGH.name == "PII_HIGH"
        assert PIIClassification.PII_MEDIUM.name == "PII_MEDIUM"


class TestClassifierColumnNameDetection:
    """Tests for column-name-based detection."""

    def test_classify_by_column_name_variations(self):
        """Test various column names are detected correctly."""
        detector = PIIDetector()

        # Email-related
        result = detector.classify_by_column_name("email")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

        result = detector.classify_by_column_name("user_email")
        assert result is not None

        # Phone-related
        result = detector.classify_by_column_name("phone")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

        result = detector.classify_by_column_name("mobile")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

        # Credit card-related
        result = detector.classify_by_column_name("credit_card")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        result = detector.classify_by_column_name("card_number")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        # Aadhaar-related
        result = detector.classify_by_column_name("aadhaar")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        # PAN-related
        result = detector.classify_by_column_name("pan")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        # SSN-related
        result = detector.classify_by_column_name("ssn")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        # Account-related
        result = detector.classify_by_column_name("account_number")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        result = detector.classify_by_column_name("bank_account")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

        # Financial-related
        result = detector.classify_by_column_name("salary")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.FINANCIAL_CONFIDENTIAL

        result = detector.classify_by_column_name("account_balance")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.FINANCIAL_CONFIDENTIAL

        # Date of birth
        result = detector.classify_by_column_name("date_of_birth")
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

    def test_unknown_column_name(self):
        """Unknown column names should return None."""
        detector = PIIDetector()
        result = detector.classify_by_column_name("created_at")
        assert result is None

        result = detector.classify_by_column_name("some_random_col")
        assert result is None

    @pytest.mark.parametrize("column", ["company", "span_id", "classname", "expansion"])
    def test_short_patterns_do_not_match_inside_words(self, column):
        """"pan" and "ssn" must not flag ordinary words that contain them."""
        assert PIIDetector().classify_by_column_name(column) is None

    @pytest.mark.parametrize(
        "column", ["pan_number", "customer_pan", "panNumber", "user-ssn", "ssn_last4"]
    )
    def test_short_patterns_match_whole_words(self, column):
        """"pan" and "ssn" must still match as words of a column name."""
        result = PIIDetector().classify_by_column_name(column)
        assert result is not None
        assert result[0] == PIIClassification.PII_HIGH

    def test_partial_column_name_match(self):
        """Partial matches within column names should work."""
        detector = PIIDetector()

        # "phone_number" should match phone
        result = detector.classify_by_column_name("phone_number")
        assert result is not None


class TestClassifierSampleValueDetection:
    """Tests for sample value-based detection."""

    def test_sample_values_email(self):
        """Email sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["user1@example.com", "user2@Test.com"]
        )
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

    def test_sample_values_credit_card(self):
        """Credit card sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["4111111111111111", "5500000000000004"]
        )
        assert result is not None
        cls, conf, reasons = result
        # Credit card should be PII_HIGH
        assert cls == PIIClassification.PII_HIGH

    def test_sample_values_pan(self):
        """PAN sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["ABCDE1234F", "XYZPN1234A"]
        )
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

    def test_sample_values_aadhaar(self):
        """Aadhaar sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["123456789012", "987654321098"]
        )
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

    def test_sample_values_ssn(self):
        """SSN sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["123-45-6789", "987-65-4321"]
        )
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_HIGH

    def test_sample_values_phone(self):
        """Phone sample values should be detected."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["9876543210", "6123456789"]
        )
        assert result is not None
        cls, conf, reasons = result
        assert cls == PIIClassification.PII_MEDIUM

    def test_sample_values_no_pii(self):
        """Non-PII sample values should result in NON_SENSITIVE."""
        detector = PIIDetector()
        result = detector.classify_by_sample_values(
            ["hello", "world", "test"]
        )
        # Should either return None or NON_SENSITIVE
        assert result is None or result[0] == PIIClassification.NON_SENSITIVE


class TestClassifierConfidenceScoring:
    """Tests for confidence scoring."""

    def test_confidence_both_methods_agree(self):
        """High confidence when column name and samples agree."""
        detector = PIIDetector()

        column_result = (PIIClassification.PII_HIGH, 0.98)
        sample_result = (PIIClassification.PII_HIGH, 0.95)

        combined = detector.calculate_confidence(column_result, sample_result)

        assert combined["confidence"] >= 0.8
        assert combined["classification"] == PIIClassification.PII_HIGH.name
        assert DetectionReason.AGREEMENT_BETWEEN_METHODS in combined["reasons"]

    def test_confidence_column_only(self):
        """Confidence from column name alone."""
        detector = PIIDetector()

        column_result = (PIIClassification.PII_HIGH, 0.98)
        sample_result = None

        combined = detector.calculate_confidence(column_result, sample_result)

        assert combined["confidence"] > 0.0
        assert combined["confidence"] <= 1.0

    def test_confidence_sample_only(self):
        """Confidence from sample values alone."""
        detector = PIIDetector()

        column_result = None
        sample_result = (PIIClassification.PII_MEDIUM, 0.90)

        combined = detector.calculate_confidence(column_result, sample_result)

        assert combined["confidence"] > 0.0
        assert combined["confidence"] <= 1.0

    def test_confidence_methods_disagree(self):
        """Lower confidence when methods disagree."""
        detector = PIIDetector()

        column_result = (PIIClassification.PII_HIGH, 0.98)
        sample_result = (PIIClassification.NON_SENSITIVE, 0.0)

        combined = detector.calculate_confidence(column_result, sample_result)

        # Should still have some confidence from column name
        assert 0.0 <= combined["confidence"] <= 1.0


class TestDetectionReasons:
    """Tests for detection reasons."""

    def test_detection_reasons_enum(self):
        """Test DetectionReason enum values."""
        assert DetectionReason.COLUMN_NAME_MATCH.value == "Column name matched"
        assert DetectionReason.SAMPLE_VALUE_REGEX.value == "Sample values matched regex pattern"
        assert DetectionReason.SAMPLE_VALUE_VALIDATION.value == "Sample values passed validation"
        assert DetectionReason.LUNH_VALIDATION.value == "Luhn checksum validation passed"
        assert DetectionReason.AGREEMENT_BETWEEN_METHODS.value == "Agreement between detection methods"


class TestRegexRulesIntegration:
    """Integration tests for RegexRules with classifier."""

    def test_luhn_validation(self):
        """Test Luhn checksum validation."""
        # Valid Luhn card number
        assert RegexRules.luhn_checksum("4111111111111111") == True
        assert RegexRules.luhn_checksum("5500000000000004") == True

        # Invalid Luhn card number
        assert RegexRules.luhn_checksum("4111111111111112") == False
        assert RegexRules.luhn_checksum("1234567890123456") == False

    def test_various_patterns(self):
        """Test various regex patterns."""
        # Email patterns
        assert RegexRules.is_email("simple@example.com")
        assert RegexRules.is_email("user.name@domain.co.uk")

        # Mobile patterns - Indian mobile numbers start with 6-9
        assert RegexRules.is_mobile("9876543210")  # starts with 9
        assert not RegexRules.is_mobile("1234567890")  # starts with 1 - invalid

        # SSN patterns
        assert RegexRules.is_ssn("123-45-6789")
        assert not RegexRules.is_ssn("123456789")

        # Date patterns
        assert RegexRules.is_date_of_birth("1990-05-15")
        assert RegexRules.is_date_of_birth("05/15/1990")