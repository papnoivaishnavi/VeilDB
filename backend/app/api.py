"""FastAPI endpoints for VeilDB schema inspection and masked queries."""

from __future__ import annotations

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import inspect

from backend.app.audit import ALLOWED, BLOCKED, ERROR, MAX_AUDIT_EVENTS, UNAUTHORIZED, AuditLog
from backend.app.database import DEFAULT_DATABASE_URL, create_database_engine, get_database_url
from backend.app.query_engine import QueryEngine, QueryEngineError
from backend.seed import seed_demo_database


engine = create_database_engine(get_database_url())
query_engine = QueryEngine(engine)
audit_log = AuditLog()

app = FastAPI(
    title="VeilDB",
    description="Schema inspection and role-aware PII masking for SQL SELECT queries.",
    version="1.0.0",
)


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=20_000)


API_KEY_ENV_VARS = {
    "ADMIN": "VEILDB_ADMIN_API_KEY",
    "SUPPORT": "VEILDB_SUPPORT_API_KEY",
    "ANALYST": "VEILDB_ANALYST_API_KEY",
}


def authenticated_role(x_api_key: str | None = Header(default=None)) -> str:
    """Resolve the caller's role from its API key; roles are never client-supplied."""
    supplied = (x_api_key or "").encode("utf-8")
    role = None
    for candidate, env_var in API_KEY_ENV_VARS.items():
        configured = os.environ.get(env_var, "").encode("utf-8")
        if configured and secrets.compare_digest(configured, supplied):
            role = candidate
    if role is None:
        audit_log.record(None, UNAUTHORIZED)
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return role


@app.on_event("startup")
def initialize_demo_database() -> None:
    """Seed the bundled local demo DB on first run; leave configured DBs untouched."""
    if (
        get_database_url() == DEFAULT_DATABASE_URL
        and not os.environ.get("DATABASE_URL")
        and not inspect(engine).get_table_names()
    ):
        seed_demo_database(engine)


@app.get("/schema")
def get_schema() -> dict:
    """List tables and column classifications detected from schema samples."""
    try:
        return query_engine.inspect_schema()
    except Exception as error:
        raise HTTPException(status_code=500, detail="Database schema inspection failed.") from error


@app.post("/query")
def run_query(request: QueryRequest, role: str = Depends(authenticated_role)) -> dict:
    """Execute a read-only SELECT and return role-masked rows and column policies."""
    tables = query_engine.referenced_tables(request.query)
    try:
        result = query_engine.execute(request.query, role)
    except QueryEngineError as error:
        audit_log.record(role, BLOCKED, tables)
        status_code = 403 if "unknown role" in str(error).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(error)) from error
    except Exception:
        audit_log.record(role, ERROR, tables)
        raise
    audit_log.record(role, ALLOWED, tables, result["row_count"])
    return result


@app.get("/audit")
def get_audit_events(
    limit: int = Query(default=100, ge=1, le=MAX_AUDIT_EVENTS),
    role: str = Depends(authenticated_role),
) -> dict:
    """Return recent audit events, newest first. Requires the ADMIN API key."""
    if role != "ADMIN":
        raise HTTPException(status_code=403, detail="The audit log requires the ADMIN role.")
    return {"events": audit_log.recent(limit)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.api:app", host="127.0.0.1", port=8000, reload=True)
