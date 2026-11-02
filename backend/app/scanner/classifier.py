"""
PII Classification Module.

This module defines the classification system for detected PII, including
confidence scoring and classification reasons.

Classification levels:
- PII_HIGH: High-confidence PII (credit cards, Aadhaar, SSN, PAN, bank accounts)
- PII_MEDIUM: Medium-confidence PII (email, phone, date of birth)
- FINANCIAL_CONFIDENTIAL: Financial data (salary, account balance)
- NON_SENSITIVE: Not classified as PII
- NEEDS_REVIEW: Ambiguous or borderline cases
"""

from typing import Optional, List, Dict, Any, Tuple
from enum import Enum, auto
from .regex_rules import RegexRules


class PIIClassification(Enum):
    """Enumeration of PII classification levels."""

    PII_HIGH = auto()
    PII_MEDIUM = auto()
    FINANCIAL_CONFIDENTIAL = auto()
    NON_SENSITIVE = auto()
    NEEDS_REVIEW = auto()


class DetectionReason(Enum):
    """Reasons for PII detection."""

    COLUMN_NAME_MATCH = "Column name matched"
    SAMPLE_VALUE_REGEX = "Sample values matched regex pattern"
    SAMPLE_VALUE_VALIDATION = "Sample values passed validation"
    LUNH_VALIDATION = "Luhn checksum validation passed"
    MULTIPLE_SAMPLES_AGREE = "Multiple samples agree on classification"
    AGREEMENT_BETWEEN_METHODS = "Agreement between detection methods"


class PIIDetector:
    """
    PII detection and classification engine.

    Combines column-name-based detection and sample-value pattern matching
    to classify columns and calculate confidence scores.
    """

    # Column name mappings to PII types
    COLUMN_PATTERNS: Dict[str, str] = {
        "email": "EMAIL",
        "phone": "PHONE",
        "mobile": "PHONE",
        "credit_card": "CREDIT_CARD",
        "card_number": "CREDIT_CARD",
        "aadhaar": "AADHAAR",
        "pan": "PAN",
        "ssn": "SSN",
        "account_number": "ACCOUNT_NUMBER",
        "bank_account": "BANK_ACCOUNT",
        "account_balance": "FINANCIAL",
        "salary": "SALARY",
        "date_of_birth": "DATE_OF_BIRTH",
        "passport_number": "PASSPORT",
    }

    # Classification mapping: PII type -> (classification, base confidence)
    TYPE_CLASSIFICATION: Dict[str, Tuple[PIIClassification, float]] = {
        "CREDIT_CARD": (PIIClassification.PII_HIGH, 0.98),
        "AADHAAR": (PIIClassification.PII_HIGH, 0.96),
        "SSN": (PIIClassification.PII_HIGH, 0.97),
        "PAN": (PIIClassification.PII_HIGH, 0.95),
        "BANK_ACCOUNT": (PIIClassification.PII_HIGH, 0.90),
        "EMAIL": (PIIClassification.PII_MEDIUM, 0.95),
        "PHONE": (PIIClassification.PII_MEDIUM, 0.90),
        "DATE_OF_BIRTH": (PIIClassification.PII_MEDIUM, 0.85),
        "SALARY": (PIIClassification.FINANCIAL_CONFIDENTIAL, 0.92),
        "ACCOUNT_NUMBER": (PIIClassification.PII_HIGH, 0.80),
        "PASSPORT": (PIIClassification.PII_HIGH, 0.93),
        "FINANCIAL": (PIIClassification.FINANCIAL_CONFIDENTIAL, 0.88),
    }

    # Financial confidential types
    FINANCIAL_TYPES = {"SALARY", "ACCOUNT_BALANCE"}

    def __init__(self):
        self.detection_reasons: List[DetectionReason] = []

    def classify_by_column_name(self, column_name: str) -> Optional[Tuple[PIIClassification, float, List[DetectionReason]]]:
        """
        Classify a column based on its name alone.

        Args:
            column_name: The database column name to check.

        Returns:
            Tuple of (classification, confidence, reasons) or None if not PII.
        """
        self.detection_reasons = []
        column_lower = column_name.lower().strip()

        if column_lower in self.COLUMN_PATTERNS:
            pii_type = self.COLUMN_PATTERNS[column_lower]
            classification, base_confidence = self.TYPE_CLASSIFICATION[pii_type]

            self.detection_reasons.append(DetectionReason.COLUMN_NAME_MATCH)

            return classification, base_confidence, list(self.detection_reasons)

        # Check for partial matches (e.g., "user_email", "phone_number")
        for pattern_name, pii_type in self.COLUMN_PATTERNS.items():
            if pattern_name in column_lower:
                classification, base_confidence = self.TYPE_CLASSIFICATION[pii_type]
                self.detection_reasons.append(DetectionReason.COLUMN_NAME_MATCH)
                return classification, base_confidence, list(self.detection_reasons)

        return None

    def classify_by_sample_values(
        self, sample_values: List[str], pii_types: Optional[List[str]] = None
    ) -> Optional[Tuple[PIIClassification, float, List[DetectionReason]]]:
        """
        Classify based on sample values pattern matching.

        Args:
            sample_values: List of sample values from the column.
            pii_types: Optional list of PII types to check against.

        Returns:
            Tuple of (classification, confidence, reasons) or None.
        """
        self.detection_reasons = []

        if not sample_values:
            return None

        # Use provided PII types or detect from values
        if pii_types is None:
            pii_types = self._detect_pii_from_values(sample_values)

        if not pii_types:
            return None

        # Calculate confidence based on how many samples match and agreement
        confidence_scores = []
        reasons = []

        for pii_type in pii_types:
            type_confidence = 0
            match_count = 0

            for value in sample_values:
                if self._value_matches_type(value, pii_type):
                    type_confidence += 1
                    match_count += 1

            if match_count > 0:
                # Normalize confidence: (matches / total samples) * base confidence
                base_conf = self.TYPE_CLASSIFICATION.get(pii_type, (PIIClassification.NON_SENSITIVE, 0.5))[1]
                normalized = (match_count / len(sample_values)) * base_conf
                confidence_scores.append(normalized)
                reasons.append(DetectionReason.SAMPLE_VALUE_REGEX)

        if not confidence_scores:
            return None

        # Use the highest confidence or average
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        max_confidence = max(confidence_scores)

        # Use the classification from the highest-confidence type
        best_type = pii_types[confidence_scores.index(max(confidence_scores))]

        if best_type in self.TYPE_CLASSIFICATION:
            classification, _ = self.TYPE_CLASSIFICATION[best_type]
        else:
            classification = PIIClassification.NON_SENSITIVE
            avg_confidence = 0.0

        # Boost confidence if multiple sample types agree
        if len(confidence_scores) > 1 and len(set(pii_types)) > 1:
            avg_confidence = min(avg_confidence + 0.05, 1.0)
            reasons.append(DetectionReason.AGREEMENT_BETWEEN_METHODS)

        return classification, round(min(avg_confidence, 1.0), 2), list(reasons)

    def _value_matches_type(self, value: str, pii_type: str) -> bool:
        """Check if a sample value matches a specific PII type."""
        if not isinstance(value, str):
            return False

        value = value.strip()

        patterns = {
            "EMAIL": RegexRules.is_email,
            "PHONE": RegexRules.is_mobile,
            "CREDIT_CARD": RegexRules.is_credit_card,
            "PAN": RegexRules.is_pan,
            "AADHAAR": RegexRules.is_aadhaar,
            "SSN": RegexRules.is_ssn,
            "BANK_ACCOUNT": RegexRules.is_bank_account,
            "DATE_OF_BIRTH": RegexRules.is_date_of_birth,
            "SALARY": RegexRules.is_salary,
            "ACCOUNT_NUMBER": RegexRules.is_account_number,
        }

        pattern_func = patterns.get(pii_type)
        if pattern_func:
            return pattern_func(value)
        return False

    def _detect_pii_from_values(
        self, sample_values: List[str]
    ) -> List[str]:
        """Detect which PII types are present in sample values.

        Checks patterns in priority order so that more specific types
        (e.g. PHONE) are detected before more generic types (e.g. SALARY,
        ACCOUNT_NUMBER) that might overlap on digit-only values. For each
        sample value, only the highest-priority matching type is recorded.
        """
        detected = []

        # Priority order: most specific patterns first
        priority_order = [
            "EMAIL",
            "PHONE",
            "CREDIT_CARD",
            "PAN",
            "AADHAAR",
            "SSN",
            "BANK_ACCOUNT",
            "ACCOUNT_NUMBER",
            "SALARY",
            "DATE_OF_BIRTH",
        ]

        for value in sample_values:
            if not isinstance(value, str) or not value.strip():
                continue

            # Check patterns in priority order; take first match
            for pii_type in priority_order:
                pattern_func = {
                    "EMAIL": RegexRules.is_email,
                    "PHONE": RegexRules.is_mobile,
                    "CREDIT_CARD": RegexRules.is_credit_card,
                    "PAN": RegexRules.is_pan,
                    "AADHAAR": RegexRules.is_aadhaar,
                    "SSN": RegexRules.is_ssn,
                    "BANK_ACCOUNT": RegexRules.is_bank_account,
                    "ACCOUNT_NUMBER": RegexRules.is_account_number,
                    "SALARY": RegexRules.is_salary,
                    "DATE_OF_BIRTH": RegexRules.is_date_of_birth,
                }[pii_type]

                if pattern_func(value) and pii_type not in detected:
                    detected.append(pii_type)
                    break  # Only take first (highest-priority) match

        return detected

    def calculate_confidence(
        self,
        column_classification: Optional[Tuple[PIIClassification, float]],
        sample_classification: Optional[Tuple[PIIClassification, float]],
        num_matching_samples: int = 0,
        total_samples: int = 0,
    ) -> Dict[str, Any]:
        """
        Calculate overall confidence score for a column classification.

        Consider:
        - Column name matches (weight: 0.4)
        - Sample value matches (weight: 0.6)
        - Number of matching samples
        - Pattern validation
        - Agreement between detection methods

        Args:
            column_classification: (classification, confidence) from column name
            sample_classification: (classification, confidence) from sample values
            num_matching_samples: Number of samples matching PII patterns
            total_samples: Total number of samples inspected

        Returns:
            Dict with 'confidence', 'classification', and 'reasons'
        """
        reasons = []
        scores = []

        # Column name contribution (weight: 0.4)
        if column_classification is not None:
            col_col, col_conf = column_classification
            scores.append(col_conf * 0.4)
            reasons.append(DetectionReason.COLUMN_NAME_MATCH)

        # Sample value contribution (weight: 0.6)
        if sample_classification is not None:
            samp_col, samp_conf = sample_classification
            # When both methods provide classifications, give full weight to sample confidence
            # The adjustment only applies when analyzing actual sample matching rates
            if num_matching_samples > 0 or total_samples > 0:
                sample_adjustment = min(num_matching_samples / max(total_samples, 1), 1.0)
            else:
                # When no sample count info is provided, use full weight
                sample_adjustment = 1.0
            adjusted_conf = samp_conf * sample_adjustment * 0.6
            scores.append(adjusted_conf)
            if num_matching_samples > 0 and total_samples > 0:
                reasons.append(DetectionReason.SAMPLE_VALUE_VALIDATION)

        # If both methods detect the same classification, boost confidence
        combined_confidence = sum(scores) if scores else 0.0

        # Agreement bonus: if both methods detect the same classification type,
        # increase confidence by up to 5%
        if column_classification is not None and sample_classification is not None:
            col_type, _ = column_classification
            samp_type, _ = sample_classification
            if col_type == samp_type:
                combined_confidence = min(combined_confidence + 0.05, 1.0)
                reasons.append(DetectionReason.AGREEMENT_BETWEEN_METHODS)

        # Determine final classification
        if combined_confidence >= 0.8:
            final_class = PIIClassification.PII_HIGH
        elif combined_confidence >= 0.5:
            final_class = PIIClassification.PII_MEDIUM
        elif combined_confidence > 0.0:
            final_class = PIIClassification.FINANCIAL_CONFIDENTIAL
        else:
            final_class = PIIClassification.NON_SENSITIVE

        return {
            "confidence": round(combined_confidence, 2),
            "classification": final_class.name,
            "reasons": reasons,
        }

    def scan_column(
        self,
        column_name: str,
        sample_values: List[Any],
    ) -> Dict[str, Any]:
        """
        Perform comprehensive scanning of a column.

        Combines column-name and sample-value detection for a complete
        classification.

        Args:
            column_name: The database column name.
            sample_values: List of sample values from the column.

        Returns:
            Dict with classification, detected_type, confidence, and reasons.
        """
        # Step 1: Classify by column name
        column_result = self.classify_by_column_name(column_name)

        # Step 2: Classify by sample values
        sample_result = self.classify_by_sample_values(sample_values) if sample_values else None

        # Step 3: Calculate combined confidence
        column_class = (
            (column_result[0], column_result[1]) if column_result else None
        )
        sample_class = (
            (sample_result[0], sample_result[1]) if sample_result else None
        )

        combined = self.calculate_confidence(column_class, sample_class)

        # Determine the primary detected type
        detected_type = "NON_SENSITIVE"
        if combined["classification"] != PIIClassification.NON_SENSITIVE:
            # Map classification to detected type name
            type_map = {
                PIIClassification.PII_HIGH: "SENSITIVE",
                PIIClassification.PII_MEDIUM: "SENSITIVE",
                PIIClassification.FINANCIAL_CONFIDENTIAL: "FINANCIAL",
            }
            detected_type = type_map.get(combined["classification"], "SENSITIVE")

        return {
            "classification": combined["classification"].name,
            "detected_type": detected_type,
            "confidence": combined["confidence"],
            "detection_reasons": combined["reasons"],
        }


# Provide a convenience instance for direct use
default_detector = PIIDetector()