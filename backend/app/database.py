"""SQLAlchemy engine and schema adapter for VeilDB."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy import column, create_engine, inspect, select, table
from sqlalchemy.engine import Engine, make_url

from backend.app.scanner.schema_scanner import SchemaScanAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "backend" / "demo.sqlite3"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"


def get_database_url() -> str:
    """Read the configured database URL, defaulting to the bundled SQLite demo."""
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def create_database_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine, preparing parent directories for SQLite files."""
    url_string = database_url or get_database_url()
    url = make_url(url_string)
    connect_args: dict[str, Any] = {}

    if url.get_backend_name() == "sqlite":
        connect_args["check_same_thread"] = False
        sqlite_path = url.database
        if sqlite_path and sqlite_path != ":memory:" and not sqlite_path.startswith("file:"):
            Path(sqlite_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

    return create_engine(url_string, future=True, pool_pre_ping=True, connect_args=connect_args)


class SqlAlchemySchemaAdapter(SchemaScanAdapter):
    """Provide the interface Member 1's SchemaScanner expects."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def get_tables(self) -> list[str]:
        inspector = inspect(self.engine)
        return sorted(set(inspector.get_table_names()) | set(inspector.get_view_names()))

    def get_columns(self, table_name: str) -> list[dict[str, Any]]:
        inspector = inspect(self.engine)
        if table_name not in set(inspector.get_table_names()) | set(inspector.get_view_names()):
            raise ValueError(f"Unknown table: {table_name}")
        return [
            {
                "name": item["name"],
                "type": str(item["type"]),
                "nullable": bool(item.get("nullable", True)),
            }
            for item in inspector.get_columns(table_name)
        ]

    def get_sample_values(self, table_name: str, column_name: str, limit: int = 10) -> list[Any]:
        if limit < 1:
            return []
        inspector = inspect(self.engine)
        if table_name not in set(inspector.get_table_names()) | set(inspector.get_view_names()):
            raise ValueError(f"Unknown table: {table_name}")
        column_names = {item["name"] for item in inspector.get_columns(table_name)}
        if column_name not in column_names:
            raise ValueError(f"Unknown column {column_name!r} in table {table_name!r}")

        reflected_table = table(
            table_name,
            *(column(name) for name in column_names),
        )
        selected_column = reflected_table.c[column_name]
        with self.engine.connect() as connection:
            result = connection.execute(
                select(selected_column).where(selected_column.is_not(None)).limit(limit)
            )
            return [row[0] for row in result]
