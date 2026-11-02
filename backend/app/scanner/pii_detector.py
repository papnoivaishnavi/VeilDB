"""
Automated PII Detection Engine.

Main detector class that combines column-name-based detection and
sample-value pattern matching to identify personally identifiable information
in database columns.

This is the primary interface for the PII scanning functionality.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
from .regex_rules import RegexRules
from .classifier import PIIClassification, DetectionReason
from .classifier import PIIDetector as ClassifierPIIDetector


class PIIScanResult:
    """
    Result of a PII scan operation.

    Holds the classification metadata for a single column.
    """

    def __init__(
        self,
        column_name: str,
        classification: PIIClassification,
        detected_type: str,
        confidence: float,
        detection_reasons: List[DetectionReason],
    ):
        self.column_name = column_name
        self.classification = classification
        self.detected_type = detected_type
        self.confidence = confidence
        self.detection_reasons = detection_reasons

    def __getitem__(self, key: str) -> Any:
        """Enable subscript access for result attributes."""
        classification = self.classification
        if hasattr(classification, "name"):
            classification = classification.name
        return {
            "column_name": self.column_name,
            "classification": classification,
            "detected_type": self.detected_type,
            "confidence": self.confidence,
            "detection_reasons": [r.value for r in self.detection_reasons],
        }.get(key)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        classification = self.classification
        if hasattr(classification, "name"):
            classification = classification.name
        return {
            "column_name": self.column_name,
            "classification": classification,
            "detected_type": self.detected_type,
            "confidence": self.confidence,
            "detection_reasons": [r.value for r in self.detection_reasons],
        }

    def __repr__(self):
        return f"PIIScanResult(col={self.column_name}, class={self.classification.name}, conf={self.confidence})"


class PIIDetector:
    """
    Main PII detection engine.

    Provides methods for detecting PII in column names and sample values,
    calculating confidence scores, and generating structured metadata.
    """

    def __init__(self):
        self._classifier = ClassifierPIIDetector()

    def classify_by_column_name(self, column_name: str) -> Optional[
        Tuple[PIIClassification, float, List[DetectionReason]]
    ]:
        """Delegate to the underlying classifier."""
        return self._classifier.classify_by_column_name(column_name)

    def classify_by_sample_values(
        self, sample_values: List[Any], pii_types: Optional[List[str]] = None
    ) -> Optional[Tuple[PIIClassification, float, List[DetectionReason]]]:
        """Delegate to the underlying classifier."""
        return self._classifier.classify_by_sample_values(sample_values, pii_types)

    def calculate_confidence(
        self,
        column_classification: Optional[Tuple[PIIClassification, float]],
        sample_classification: Optional[Tuple[PIIClassification, float]],
        num_matching_samples: int = 0,
        total_samples: int = 0,
    ) -> Dict[str, Any]:
        """Delegate to the underlying classifier."""
        return self._classifier.calculate_confidence(
            column_classification,
            sample_classification,
            num_matching_samples,
            total_samples,
        )

    def detect_by_column_name(
        self, column_name: str
    ) -> Optional[PIIScanResult]:
        """
        Detect PII based on column name alone.

        Uses the classifier module to determine if the column name
        matches any known PII patterns.

        Args:
            column_name: The database column name to analyze.

        Returns:
            PIIScanResult if PII detected, None otherwise.
        """
        column_result = self._classifier.classify_by_column_name(column_name)

        if column_result is None:
            return None

        classification, confidence, reasons = column_result
        detected_type = self._get_detected_type(classification)

        return PIIScanResult(
            column_name=column_name,
            classification=classification,
            detected_type=detected_type,
            confidence=confidence,
            detection_reasons=reasons,
        )

    def detect_by_sample_values(
        self, sample_values: List[Any]
    ) -> Optional[PIIScanResult]:
        """
        Detect PII based on sample values pattern matching.

        Args:
            sample_values: List of sample values from the column.

        Returns:
            PIIScanResult if PII detected, None otherwise.
        """
        # Filter to strings only
        string_values = [str(v) for v in sample_values if isinstance(v, str)]

        if not string_values:
            return None

        # Use the classifier's method to detect by sample values
        sample_result = self._classifier.classify_by_sample_values(string_values)

        if sample_result is None:
            return None

        classification, confidence, reasons = sample_result
        detected_type = self._get_detected_type(classification)

        return PIIScanResult(
            column_name="<sample_values>",
            classification=classification,
            detected_type=detected_type,
            confidence=confidence,
            detection_reasons=reasons,
        )

    def detect_column(
        self,
        column_name: str,
        sample_values: Optional[List[Any]] = None,
    ) -> PIIScanResult:
        """
        Comprehensive detection combining column name and sample values.

        This is the primary method for scanning a column. It first tries
        column-name-based detection, then complements with sample-value
        analysis.

        Args:
            column_name: The database column name.
            sample_values: Optional list of sample values from the column.

        Returns:
            PIIScanResult with complete classification metadata.
        """
        # Start with column name detection
        column_result = self.detect_by_column_name(column_name)

        # If no sample values provided, return column-name result
        if sample_values is None:
            if column_result:
                return column_result
            # Fallback: return NON_SENSITIVE result
            return PIIScanResult(
                column_name=column_name,
                classification=PIIClassification.NON_SENSITIVE,
                detected_type="NON_SENSITIVE",
                confidence=0.0,
                detection_reasons=[],
            )

        # Sample value detection
        sample_result = self.detect_by_sample_values(sample_values)

        # If column name detected but samples don't match,
        # we still trust the column name but lower confidence slightly
        if column_result and sample_result:
            # Combine both results using the classifier's confidence calculation
            column_class = column_result.classification
            col_conf = column_result.confidence
            col_reasons = column_result.detection_reasons

            samp_class = sample_result.classification
            samp_conf = sample_result.confidence
            samp_reasons = sample_result.detection_reasons

            # Use the classifier's calculate_confidence
            combined = self._classifier.calculate_confidence(
                (column_class, col_conf),
                (samp_class, samp_conf),
                num_matching_samples=sum(
                    1 for v in sample_values if isinstance(v, str)
                ),
                total_samples=len(sample_values),
            )

            # Build result with combined classification
            if combined["confidence"] > 0.5:
                result_conf = combined["confidence"]
                result_class = combined["classification"]
                # The classifier exposes classification names as strings in
                # its confidence result, while PIIScanResult consumers expect
                # the PIIClassification enum (for example SchemaScanner uses
                # ``result.classification.name``).
                if isinstance(result_class, str):
                    result_class = PIIClassification[result_class]
                result_reasons = combined["reasons"]
                result_detected = self._get_detected_type(result_class)
            else:
                # Use column name result if combined confidence is low
                result_conf = col_conf
                result_class = column_class
                result_reasons = col_reasons
                result_detected = self._get_detected_type(result_class)

            return PIIScanResult(
                column_name=column_name,
                classification=result_class,
                detected_type=result_detected,
                confidence=result_conf,
                detection_reasons=result_reasons,
            )

        # Return whichever result is available
        if column_result:
            return column_result
        if sample_result:
            return sample_result

        # Fallback: no PII detected
        return PIIScanResult(
            column_name=column_name,
            classification=PIIClassification.NON_SENSITIVE,
            detected_type="NON_SENSITIVE",
            confidence=0.0,
            detection_reasons=[],
        )

    def scan_column(
        self,
        column_name: str,
        sample_values: List[Any],
    ) -> PIIScanResult:
        """
        Scan a column for PII (comprehensive version).

        This is a convenience method that combines column-name and
        sample-value detection.

        Args:
            column_name: The database column name.
            sample_values: List of sample values from the column.

        Returns:
            PIIScanResult with complete classification metadata.
        """
        return self.detect_column(column_name, sample_values)

    def scan_database(
        self,
        connection_or_adapter: Any,
        sample_limit: int = 10,
    ) -> Dict[str, Any]:
        """
        Scan a database for PII columns.

        This method accepts a database connection or a schema-inspection adapter.
        It retrieves tables, columns, and sample values, then detects PII in each column.

        Args:
            connection_or_adapter: A database connection object or adapter that
                implements .get_tables(), .get_columns(table), and .get_sample_values(table, column).
            sample_limit: Maximum number of sample values to inspect per column.

        Returns:
            Dict with table metadata and column classifications, structured for
            integration with Member 2's metadata registry.

            Example format:
            {
                "table": "customers",
                "columns": {
                    "credit_card": {
                        "classification": "PII_HIGH",
                        "detected_type": "CREDIT_CARD",
                        "confidence": 0.98,
                        "detection_reasons": [
                            "Column name matched credit_card",
                            "Sample values passed card validation"
                        ]
                    }
                }
            }

        """
        # This is a placeholder - the actual implementation depends on Member 2's
        # database connector. The interface is designed to be adaptable.
        # Member 2 should implement an adapter that provides:
        # - get_tables() -> List[str]
        # - get_columns(table) -> List[Dict] with 'name' and 'type' keys
        # - get_sample_values(table, column, limit) -> List[Any]

        return {}

    def _get_detected_type(self, classification: PIIClassification) -> str:
        """
        Map classification to a detected type string.

        Args:
            classification: The PIIClassification enum value.

        Returns:
            String representation of the detected type.
        """
        type_map = {
            PIIClassification.PII_HIGH: "SENSITIVE",
            PIIClassification.PII_MEDIUM: "SENSITIVE",
            PIIClassification.FINANCIAL_CONFIDENTIAL: "FINANCIAL",
            PIIClassification.NON_SENSITIVE: "NON_SENSITIVE",
            PIIClassification.NEEDS_REVIEW: "REVIEW",
        }
        return type_map.get(classification, "SENSITIVE")


# Provide a convenience instance
default_detector = PIIDetector()
