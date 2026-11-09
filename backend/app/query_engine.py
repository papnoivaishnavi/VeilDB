"""Read-only SQL query execution with detector-driven, role-based masking."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from backend.app.database import SqlAlchemySchemaAdapter
from backend.app.masking.masking_engine import MaskingEngine
from backend.app.scanner.pii_detector import PIIDetector
from backend.app.scanner.schema_scanner import SchemaScanner
from backend.app.security.rbac import Classification, RBAC, Role


MAX_RESULT_ROWS = 500
_BLOCKED_SQL_WORDS = {
    "ALTER",
    "ATTACH",
    "CALL",
    "COPY",
    "CREATE",
    "DELETE",
    "DETACH",
    "DROP",
    "EXEC",
    "EXECUTE",
    "INSERT",
    "INTO",
    "PRAGMA",
    "REPLACE",
    "TRUNCATE",
    "UPDATE",
    "VACUUM",
}
_CLASSIFICATION_SENSITIVITY = {
    "NON_SENSITIVE": 0,
    "PII_MEDIUM": 1,
    "FINANCIAL_CONFIDENTIAL": 2,
    "PII_HIGH": 3,
    "NEEDS_REVIEW": 4,
}
_STRATEGY_RESTRICTIVENESS = {"FULL": 0, "PARTIAL": 1, "HASH": 2, "REDACT": 3}
_SQLGLOT_DIALECTS = {
    "sqlite": "sqlite",
    "postgresql": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "mssql": "tsql",
    "oracle": "oracle",
}


class QueryEngineError(ValueError):
    """A query or role was rejected before database results were returned."""


def _sql_tokens(statement: str) -> list[tuple[str, str, int]]:
    """Tokenize enough SQL to validate one SELECT and inspect its projection."""
    tokens: list[tuple[str, str, int]] = []
    index = 0
    depth = 0
    length = len(statement)

    while index < length:
        char = statement[index]
        if char.isspace():
            index += 1
            continue

        if statement.startswith("--", index):
            newline = statement.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue

        if statement.startswith("/*", index):
            end = statement.find("*/", index + 2)
            if end < 0:
                raise QueryEngineError("SQL contains an unclosed comment.")
            index = end + 2
            continue

        if char == "'":
            index += 1
            while index < length:
                if statement[index] == "'":
                    if index + 1 < length and statement[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            else:
                raise QueryEngineError("SQL contains an unclosed string literal.")
            continue

        if char in ('"', "`", "["):
            closing = "]" if char == "[" else char
            index += 1
            identifier: list[str] = []
            while index < length:
                if statement[index] == closing:
                    if index + 1 < length and statement[index + 1] == closing:
                        identifier.append(closing)
                        index += 2
                        continue
                    index += 1
                    break
                identifier.append(statement[index])
                index += 1
            else:
                raise QueryEngineError("SQL contains an unclosed quoted identifier.")
            tokens.append(("identifier", "".join(identifier), depth))
            continue

        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (statement[end].isalnum() or statement[end] in "_$"):
                end += 1
            tokens.append(("word", statement[index:end], depth))
            index = end
            continue

        if char.isdigit():
            end = index + 1
            while end < length and (statement[end].isalnum() or statement[end] in "._"):
                end += 1
            tokens.append(("number", statement[index:end], depth))
            index = end
            continue

        if char == "(":
            tokens.append(("symbol", char, depth))
            depth += 1
            index += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            tokens.append(("symbol", char, depth))
            index += 1
            continue

        tokens.append(("symbol", char, depth))
        index += 1

    return tokens


def _validate_select(statement: str) -> list[tuple[str, str, int]]:
    if not statement or not statement.strip():
        raise QueryEngineError("Enter a SELECT query.")

    tokens = _sql_tokens(statement)
    if not tokens or tokens[0][0] != "word" or tokens[0][1].upper() != "SELECT":
        raise QueryEngineError("Only SELECT queries are allowed.")

    semicolons = [index for index, token in enumerate(tokens) if token[1] == ";"]
    if len(semicolons) > 1 or (semicolons and semicolons[0] != len(tokens) - 1):
        raise QueryEngineError("Run one SELECT statement at a time.")

    forbidden = [
        value.upper()
        for kind, value, _ in tokens
        if kind == "word" and value.upper() in _BLOCKED_SQL_WORDS
    ]
    if forbidden:
        raise QueryEngineError("This read-only query contains a prohibited SQL operation.")
    return tokens


def _projection_tokens(tokens: list[tuple[str, str, int]]) -> list[list[tuple[str, str, int]]]:
    """Return top-level SELECT expressions, split on commas before FROM."""
    select_index = next(
        (index for index, token in enumerate(tokens) if token[0] == "word" and token[1].upper() == "SELECT"),
        None,
    )
    if select_index is None:
        return []
    start = select_index + 1
    if start < len(tokens) and tokens[start][0] == "word" and tokens[start][1].upper() in {"DISTINCT", "ALL"}:
        start += 1

    from_index = next(
        (
            index
            for index in range(start, len(tokens))
            if tokens[index][0] == "word"
            and tokens[index][1].upper() == "FROM"
            and tokens[index][2] == 0
        ),
        len(tokens),
    )
    expressions: list[list[tuple[str, str, int]]] = []
    current: list[tuple[str, str, int]] = []
    for token in tokens[start:from_index]:
        if token[1] == "," and token[2] == 0:
            expressions.append(current)
            current = []
        else:
            current.append(token)
    if current:
        expressions.append(current)
    return expressions


def _alias_classifications(
    tokens: list[tuple[str, str, int]],
    known_classifications: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Trace explicit SQL aliases back to sensitive columns in their expressions."""
    aliases: dict[str, list[str]] = {}
    for index, token in enumerate(tokens):
        if token[0] != "word" or token[1].upper() != "AS" or index + 1 >= len(tokens):
            continue
        alias_kind, alias_name, depth = tokens[index + 1]
        if alias_kind not in {"word", "identifier"}:
            continue

        expression: list[tuple[str, str, int]] = []
        cursor = index - 1
        while cursor >= 0:
            previous = tokens[cursor]
            if previous[2] == depth and (
                previous[1] == ","
                or (previous[0] == "word" and previous[1].upper() in {"SELECT", "FROM"})
            ):
                break
            expression.append(previous)
            cursor -= 1

        candidates: list[str] = []
        for kind, identifier, _ in reversed(expression):
            if kind in {"word", "identifier"}:
                candidates.extend(known_classifications.get(identifier.casefold(), []))
                candidates.extend(aliases.get(identifier.casefold(), []))
        if candidates:
            aliases.setdefault(alias_name.casefold(), []).extend(candidates)
    return aliases


def _restrict_query(
    statement: str,
    dialect_name: str,
    known_tables: set[str],
    known_columns: set[str],
    masked_columns: set[str],
) -> str:
    """Reject queries that could reveal masked data and return the SQL to execute.

    A masked column may only appear as a plain output column, where it is masked.
    Using it anywhere else (filters, joins, sorting, or expressions) would reveal
    information about the raw value, so those queries are refused. Returning the
    regenerated SQL ensures the database runs exactly what was analyzed here.
    """
    dialect = _SQLGLOT_DIALECTS.get(dialect_name)
    try:
        tree = sqlglot.parse_one(statement, dialect=dialect)
    except SqlglotError as error:
        raise QueryEngineError("The SELECT query could not be analyzed.") from error

    if not isinstance(tree, exp.Select) or sum(1 for _ in tree.find_all(exp.Select)) != 1:
        raise QueryEngineError("This role can only run a single SELECT without UNION or subqueries.")

    for source in tree.find_all(exp.Table):
        if source.name.casefold() not in known_tables:
            raise QueryEngineError("This role can only query scanned tables.")

    sort_keys = [ordered.this for order in tree.find_all(exp.Order) for ordered in order.expressions]
    group_keys = [key for group in tree.find_all(exp.Group) for key in group.expressions]
    if any(key.is_int for key in sort_keys + group_keys):
        raise QueryEngineError("This role must sort and group by column name, not position.")

    blocked = set(masked_columns)
    allowed_nodes: list[exp.Column] = []
    aliases: set[str] = set()
    for projection in tree.expressions:
        alias = projection.alias.casefold()
        if alias:
            aliases.add(alias)
        source_column = projection.unalias()
        if isinstance(source_column, exp.Column) and source_column.name.casefold() in masked_columns:
            allowed_nodes.append(source_column)
            if alias:
                blocked.add(alias)

    for column in tree.find_all(exp.Column):
        if column.is_star:
            continue
        name = column.name.casefold()
        if name not in known_columns and name not in aliases:
            raise QueryEngineError(f"Unknown column for this role: {column.name}.")
        if name in blocked and not any(column is node for node in allowed_nodes):
            raise QueryEngineError(
                f"Masked column {column.name} can only be selected directly for this role."
            )

    return tree.sql(dialect=dialect)


def _safe_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return None
    return value


class QueryEngine:
    """Inspect a database and execute SELECT statements through PII masking."""

    def __init__(
        self,
        engine: Engine,
        detector: PIIDetector | None = None,
        masker: MaskingEngine | None = None,
        max_rows: int = MAX_RESULT_ROWS,
    ):
        self.engine = engine
        self.adapter = SqlAlchemySchemaAdapter(engine)
        self.detector = detector or PIIDetector()
        self.masker = masker or MaskingEngine()
        self.max_rows = max(1, max_rows)

    def referenced_tables(self, statement: str) -> list[str]:
        """Return the existing tables a statement names, for the audit log.

        Names are checked against the database so that arbitrary text placed in
        a table position is never recorded. Auditing must not affect the query,
        so an unparsable statement or a failed lookup yields no tables.
        """
        dialect = _SQLGLOT_DIALECTS.get(self.engine.dialect.name)
        try:
            known_tables = {name.casefold(): name for name in self.adapter.get_tables()}
            tree = sqlglot.parse_one(statement, dialect=dialect)
        except (SqlglotError, SQLAlchemyError, RecursionError):
            return []
        referenced = {source.name.casefold() for source in tree.find_all(exp.Table)}
        return [known_tables[name] for name in referenced if name in known_tables]

    def inspect_schema(self) -> dict[str, Any]:
        """Return SQLAlchemy column metadata annotated with Member 1's scan results."""
        result, _ = self._inspect_schema()
        return result

    def _inspect_schema(self) -> tuple[dict[str, Any], dict[str, list[str]]]:
        scan = SchemaScanner(self.adapter, self.detector).scan_database()
        classification_by_column: dict[str, list[str]] = {}
        table_results: list[dict[str, Any]] = []
        total_columns = 0
        pii_columns = 0

        for table_scan in scan["results"]:
            table_name = table_scan["table"]
            scanned_columns = table_scan["columns"]
            column_info = self.adapter.get_columns(table_name)
            info_by_name = {item["name"]: item for item in column_info}
            columns: dict[str, dict[str, Any]] = {}

            for name, detection in scanned_columns.items():
                classification = str(detection.get("classification", "NON_SENSITIVE"))
                info = info_by_name.get(name, {})
                reasons = detection.get("detection_reasons", [])
                columns[name] = {
                    "type": info.get("type", ""),
                    "nullable": info.get("nullable", True),
                    "classification": classification,
                    "detected_type": detection.get("detected_type", "NON_SENSITIVE"),
                    "confidence": float(detection.get("confidence", 0.0)),
                    "detection_reasons": [
                        reason.value if hasattr(reason, "value") else str(reason)
                        for reason in reasons
                    ],
                }
                classification_by_column.setdefault(name.casefold(), []).append(classification)
                total_columns += 1
                if classification != "NON_SENSITIVE":
                    pii_columns += 1

            table_results.append({"table": table_name, "columns": columns})

        return {
            "tables_scanned": len(table_results),
            "total_columns": total_columns,
            "pii_columns": pii_columns,
            "results": table_results,
        }, classification_by_column

    def execute(self, statement: str, role_name: str) -> dict[str, Any]:
        """Execute one SELECT and mask every output column according to its role."""
        normalized_role = role_name.strip().upper() if isinstance(role_name, str) else role_name
        role = RBAC.get_role(normalized_role)
        if role == Role.UNKNOWN:
            raise QueryEngineError("Unknown role. Choose ADMIN, SUPPORT, or ANALYST.")

        tokens = _validate_select(statement)
        schema, known_classifications = self._inspect_schema()
        masked_columns = {
            name
            for name, classifications in known_classifications.items()
            if any(
                RBAC.get_masking_policy(role, RBAC.get_classification(item.upper())) != "FULL"
                for item in classifications
            )
        }
        if masked_columns:
            statement = _restrict_query(
                statement,
                self.engine.dialect.name,
                {item["table"].casefold() for item in schema["results"]},
                set(known_classifications),
                masked_columns,
            )
            tokens = _validate_select(statement)
        expressions = _projection_tokens(tokens)
        aliases = _alias_classifications(tokens, known_classifications)
        referenced_classifications = [
            classification
            for kind, identifier, _ in tokens
            if kind in {"word", "identifier"}
            for classification in known_classifications.get(identifier.casefold(), [])
        ]

        try:
            with self.engine.connect() as connection:
                if connection.dialect.name == "sqlite":
                    # Keep the pooled SQLite connection read-only after this point.
                    connection.exec_driver_sql("PRAGMA query_only = ON")
                result = connection.execute(text(statement))
                raw_names = list(result.keys())
                rows = result.fetchmany(self.max_rows + 1)
        except SQLAlchemyError as error:
            raise QueryEngineError("The SELECT query could not be executed against this database.") from error

        if len(rows) > self.max_rows:
            raise QueryEngineError(f"The query returned more than {self.max_rows} rows. Add a LIMIT clause.")

        names = self._unique_names(raw_names)
        output_values = [
            [_safe_value(row[index]) for row in rows]
            for index in range(len(names))
        ]
        column_metadata: list[dict[str, str]] = []
        for index, (name, raw_name) in enumerate(zip(names, raw_names)):
            candidates = list(known_classifications.get(str(raw_name).split(".")[-1].casefold(), []))

            if index < len(expressions):
                for kind, identifier, _ in expressions[index]:
                    if kind in {"word", "identifier"}:
                        candidates.extend(known_classifications.get(identifier.casefold(), []))
                        candidates.extend(aliases.get(identifier.casefold(), []))
                    elif identifier == "*":
                        candidates.extend(referenced_classifications)

            # Scan result samples as well, which catches PII passed through aliases
            # or selected from columns that were not named as PII in the schema.
            detected = self.detector.detect_column(name, output_values[index])
            candidates.append(detected.classification.name)

            classification, strategy = self._most_restrictive_policy(role, candidates)
            column_metadata.append(
                {"name": name, "classification": classification, "strategy": strategy}
            )

        masked_rows: list[dict[str, Any]] = []
        for row_index in range(len(rows)):
            masked_row: dict[str, Any] = {}
            for column_index, metadata in enumerate(column_metadata):
                masked_row[metadata["name"]] = self.masker.mask_value(
                    output_values[column_index][row_index],
                    strategy=metadata["strategy"],
                    context={"role": role.value, "column": metadata["name"]},
                )
            masked_rows.append(masked_row)

        return {
            "role": role.value,
            "columns": column_metadata,
            "row_count": len(masked_rows),
            "rows": masked_rows,
        }

    @staticmethod
    def _unique_names(names: list[str]) -> list[str]:
        seen: dict[str, int] = {}
        unique: list[str] = []
        for raw_name in names:
            name = str(raw_name)
            seen[name] = seen.get(name, 0) + 1
            unique.append(name if seen[name] == 1 else f"{name}_{seen[name]}")
        return unique

    @staticmethod
    def _most_restrictive_policy(role: Role, candidates: list[str]) -> tuple[str, str]:
        normalized = {item.upper() for item in candidates}
        if not normalized:
            normalized = {"NEEDS_REVIEW"}
        try:
            classifications = [RBAC.get_classification(item) for item in normalized]
        except ValueError as error:
            raise QueryEngineError("A query column has an unsupported PII classification.") from error

        policies: list[tuple[int, int, Classification, str]] = []
        for classification in classifications:
            strategy = RBAC.get_masking_policy(role, classification)
            policies.append(
                (
                    _STRATEGY_RESTRICTIVENESS[strategy],
                    _CLASSIFICATION_SENSITIVITY[classification.value],
                    classification,
                    strategy,
                )
            )
        _, _, selected_classification, selected_strategy = max(policies, key=lambda item: (item[0], item[1]))
        return selected_classification.value, selected_strategy
