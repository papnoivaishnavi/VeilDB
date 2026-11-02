"""
Schema Scanning Module.

Implements a scanner that accepts a database connection or a schema-inspection
adapter. Retrieves tables, column names and data types, inspects sample values,
detects sensitive columns, and generates classification results.

This module defines the interface that Member 2 can implement to connect their
database connector (PostgreSQL, SQLite, etc.) to the PII detection system.

The scanner is designed to be adapter-friendly - it does not implement database
connectivity itself but defines a documented interface.
"""

from typing import Any, Dict, List, Optional, Tuple
from .pii_detector import PIIDetector, PIIScanResult, PIIClassification
from .regex_rules import RegexRules


class SchemaScanAdapter:
    """
    Abstract adapter for database schema inspection.

    Member 2 should implement this adapter (or a compatible one) to connect
    their database connector (PostgreSQL, SQLite, etc.) to the PII detection system.

    The adapter must implement:
    - get_tables() -> List[str]: Retrieve all table names
    - get_columns(table_name: str) -> List[Dict]: Retrieve column info for a table
      Each dict should have 'name' and 'type' keys
    - get_sample_values(table_name: str, column_name: str, limit: int = 10) -> List[Any]
      Retrieve sample values for a column
    """

    def get_tables(self) -> List[str]:
        """
        Retrieve all table names from the database.

        Returns:
            List of table name strings.
        """
        raise NotImplementedError("Subclasses must implement get_tables()")

    def get_columns(self, table_name: str) -> List[Dict[str, str]]:
        """
        Retrieve column names and data types for a table.

        Args:
            table_name: Name of the table to inspect.

        Returns:
            List of dicts, each with 'name' and 'type' keys representing
            a column in the table.
        """
        raise NotImplementedError("Subclasses must implement get_columns()")

    def get_sample_values(
        self, table_name: str, column_name: str, limit: int = 10
    ) -> List[Any]:
        """
        Retrieve sample values for a column.

        Args:
            table_name: Name of the table.
            column_name: Name of the column.
            limit: Maximum number of sample values to retrieve.

        Returns:
            List of sample values (could be strings, ints, floats, None, etc.).
        """
        raise NotImplementedError("Subclasses must implement get_sample_values()")


class SchemaScanner:
    """
    Scanner that inspects database schemas for PII columns.

    Accepts a SchemaScanAdapter instance and performs automated PII detection
    on all columns across all tables.

    Does not implement database connectivity - Member 2 provides the adapter.
    """

    def __init__(self, adapter: SchemaScanAdapter, detector: Optional[PIIDetector] = None):
        """
        Initialize the schema scanner.

        Args:
            adapter: A SchemaScanAdapter instance connecting to a database.
            detector: Optional PIIDetector instance; if not provided, a default one is used.
        """
        self.adapter = adapter
        self.detector = detector or PIIDetector()

    def scan_table(self, table_name: str, sample_limit: int = 10) -> Dict[str, Any]:
        """
        Scan a single table for PII columns.

        Args:
            table_name: Name of the table to scan.
            sample_limit: Maximum number of sample values to inspect per column.

        Returns:
            Dict with column classifications in the format:
            {
                "table": table_name,
                "columns": {
                    "column_name": {
                        "classification": "PII_HIGH|PII_MEDIUM|FINANCIAL_CONFIDENTIAL|NON_SENSITIVE|NEEDS_REVIEW",
                        "detected_type": "CREDIT_CARD|EMAIL|PHONE|...|NON_SENSITIVE",
                        "confidence": float 0-1,
                        "detection_reasons": [str]
                    }
                }
            }
        """
        columns_info = self.adapter.get_columns(table_name)
        columns_result = {}

        for col_info in columns_info:
            column_name = col_info.get("name", "")
            column_type = col_info.get("type", "")

            # Get sample values for this column
            sample_values = self.adapter.get_sample_values(
                table_name, column_name, sample_limit
            )

            # Detect PII in this column
            scan_result = self.detector.detect_column(
                column_name, sample_values
            )

            # Store result
            columns_result[column_name] = {
                "classification": scan_result.classification.name,
                "detected_type": scan_result.detected_type,
                "confidence": scan_result.confidence,
                "detection_reasons": scan_result.detection_reasons,
            }

        return {
            "table": table_name,
            "columns": columns_result,
        }

    def scan_all_tables(self, sample_limit: int = 10) -> List[Dict[str, Any]]:
        """
        Scan all tables in the database for PII columns.

        Args:
            sample_limit: Maximum number of sample values to inspect per column.

        Returns:
            List of dicts, one per table, each with the format:
            {"table": table_name, "columns": {...}}
        """
        tables = self.adapter.get_tables()
        results = []

        for table in tables:
            result = self.scan_table(table, sample_limit)
            results.append(result)

        return results

    def scan_database(
        self, sample_limit: int = 10
    ) -> Dict[str, Any]:
        """
        Scan the entire database for PII columns.

        Aggregates results from all tables.

        Args:
            sample_limit: Maximum number of sample values to inspect per column.

        Returns:
            Dict with overall metadata:
            {
                "tables_scanned": int,
                "total_columns": int,
                "pii_columns": int,
                "results": [{"table": ..., "columns": ...}, ...]
            }
        """
        tables_results = self.scan_all_tables(sample_limit)

        total_columns = 0
        pii_columns = 0

        for table_result in tables_results:
            cols = table_result.get("columns", {})
            total_columns += len(cols)
            for col_name, col_data in cols.items():
                try:
                    if col_data.get("classification") not in (
                        "NON_SENSITIVE",
                    ):
                        pii_columns += 1
                except (AttributeError, TypeError):
                    pass

        return {
            "tables_scanned": len(tables_results),
            "total_columns": total_columns,
            "pii_columns": pii_columns,
            "results": tables_results,
        }


# Provide a convenience function for direct use
def scan_with_adapter(
    adapter: SchemaScanAdapter,
    sample_limit: int = 10,
) -> Dict[str, Any]:
    """
    Convenience function to scan a database using an adapter.

    Args:
        adapter: A SchemaScanAdapter instance.
        sample_limit: Maximum number of sample values to inspect per column.

    Returns:
        Structured metadata dict suitable for Member 2's metadata registry.
    """
    scanner = SchemaScanner(adapter)
    return scanner.scan_database(sample_limit)