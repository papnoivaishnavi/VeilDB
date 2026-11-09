"""Tests for the audit trail, using fictional seed data."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app import api
from backend.app.audit import AuditLog
from backend.app.query_engine import QueryEngine
from backend.seed import seed_demo_database


ADMIN = {"X-API-Key": "admin-test-key"}
ANALYST = {"X-API-Key": "analyst-test-key"}
SECRET = "priya.secret@example.com"


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    seed_demo_database(engine)
    monkeypatch.setattr(api, "query_engine", QueryEngine(engine))
    monkeypatch.setattr(api, "audit_log", AuditLog())
    monkeypatch.setenv("VEILDB_ADMIN_API_KEY", "admin-test-key")
    monkeypatch.setenv("VEILDB_SUPPORT_API_KEY", "support-test-key")
    monkeypatch.setenv("VEILDB_ANALYST_API_KEY", "analyst-test-key")
    return TestClient(api.app)


def events(client):
    return client.get("/audit", headers=ADMIN).json()["events"]


def test_allowed_query_is_recorded(client):
    client.post("/query", json={"query": "SELECT id FROM customers LIMIT 2"}, headers=ANALYST)
    event = events(client)[0]
    assert event["role"] == "ANALYST"
    assert event["outcome"] == "ALLOWED"
    assert event["tables"] == ["customers"]
    assert event["row_count"] == 2


def test_blocked_query_is_recorded(client):
    response = client.post(
        "/query", json={"query": "SELECT id FROM customers ORDER BY salary"}, headers=ANALYST
    )
    assert response.status_code == 400
    event = events(client)[0]
    assert event["outcome"] == "BLOCKED"
    assert event["tables"] == ["customers"]
    assert event["row_count"] is None


def test_invalid_api_key_is_recorded(client):
    client.post("/query", json={"query": "SELECT id FROM customers"}, headers={"X-API-Key": "wrong"})
    event = events(client)[0]
    assert event["role"] is None
    assert event["outcome"] == "UNAUTHORIZED"


def test_unexpected_failure_is_recorded(client, monkeypatch):
    def fail(statement, role):
        raise RuntimeError("database driver crashed")

    monkeypatch.setattr(api.query_engine, "execute", fail)
    with pytest.raises(RuntimeError):
        client.post("/query", json={"query": "SELECT id FROM customers"}, headers=ADMIN)
    assert events(client)[0]["outcome"] == "ERROR"


@pytest.mark.parametrize(
    "statement",
    [
        f"SELECT id FROM customers WHERE email = '{SECRET}'",
        f'SELECT id FROM "{SECRET}"',
        f"SELECT '{SECRET}' FROM",
    ],
)
def test_events_never_contain_query_text(client, statement):
    client.post("/query", json={"query": statement}, headers=ADMIN)
    client.post("/query", json={"query": statement}, headers=ANALYST)
    assert SECRET not in json.dumps(events(client))


def test_table_names_are_limited_to_existing_tables(client):
    client.post("/query", json={"query": "SELECT * FROM made_up_table"}, headers=ADMIN)
    assert events(client)[0]["tables"] == []


def test_query_still_works_when_it_cannot_be_parsed_for_audit(client):
    response = client.post("/query", json={"query": "SELECT 'unterminated"}, headers=ADMIN)
    assert response.status_code == 400
    assert events(client)[0]["outcome"] == "BLOCKED"


def test_parser_recursion_limit_does_not_break_auditing(client, monkeypatch):
    def overflow(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr("backend.app.query_engine.sqlglot.parse_one", overflow)
    assert api.query_engine.referenced_tables("SELECT 1") == []


def test_audit_requires_admin(client):
    assert client.get("/audit").status_code == 401
    assert client.get("/audit", headers=ANALYST).status_code == 403
    assert client.get("/audit", headers={"X-API-Key": "support-test-key"}).status_code == 403


@pytest.mark.parametrize("limit", [0, 1001])
def test_audit_limit_is_validated(client, limit):
    assert client.get(f"/audit?limit={limit}", headers=ADMIN).status_code == 422


def test_recent_returns_newest_first_within_limit():
    log = AuditLog()
    for count in range(3):
        log.record("ADMIN", "ALLOWED", row_count=count)
    assert [event["row_count"] for event in log.recent(2)] == [2, 1]


def test_buffer_discards_oldest_events():
    log = AuditLog(max_events=2)
    for count in range(3):
        log.record("ADMIN", "ALLOWED", row_count=count)
    assert [event["row_count"] for event in log.recent(10)] == [2, 1]
