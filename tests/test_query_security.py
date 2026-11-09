"""Security regression tests for role-aware queries, using fictional seed data."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app import api
from backend.app.masking.strategies import HMACMask
from backend.app.query_engine import QueryEngine, QueryEngineError
from backend.app.scanner.classifier import PIIDetector
from backend.seed import seed_demo_database


RAW_AADHAAR = "234567890123"


@pytest.fixture
def query_engine():
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    seed_demo_database(engine)
    return QueryEngine(engine)


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT id FROM customers WHERE 0 UNION ALL SELECT CAST(aadhaar AS INTEGER) FROM customers",
        "SELECT id FROM customers WHERE 0 UNION ALL SELECT salary FROM customers",
        "SELECT x FROM (SELECT CAST(aadhaar AS INTEGER) x FROM customers)",
        "SELECT id FROM customers WHERE id IN (SELECT id FROM customers WHERE aadhaar LIKE '2%')",
        "SELECT id FROM customers WHERE aadhaar LIKE '2345%'",
        'SELECT id FROM customers WHERE "aadhaar" LIKE \'2345%\'',
        "SELECT id FROM customers c WHERE c.aadhaar LIKE '2345%'",
        "SELECT id FROM customers WHERE /* note */ AADHAAR LIKE '2345%'",
        "SELECT id FROM customers ORDER BY salary DESC",
        "SELECT aadhaar AS department FROM customers ORDER BY department",
        "SELECT salary, id FROM customers ORDER BY 1",
        "SELECT salary FROM customers GROUP BY 1",
        "SELECT substr(aadhaar, 1, 1) FROM customers",
        "SELECT aadhaar LIKE '2%' FROM customers",
        "SELECT CASE WHEN aadhaar LIKE '2%' THEN 1 ELSE 0 END FROM customers",
        "SELECT id, rank() OVER (ORDER BY salary) FROM customers",
        "SELECT sql FROM sqlite_master",
        "SELECT customers FROM customers",
    ],
)
def test_analyst_cannot_extract_masked_data(query_engine, statement):
    with pytest.raises(QueryEngineError):
        query_engine.execute(statement, "ANALYST")


def test_support_cannot_shorten_a_value_to_avoid_partial_masking(query_engine):
    with pytest.raises(QueryEngineError):
        query_engine.execute("SELECT substr(aadhaar, 1, 8) FROM customers", "SUPPORT")


def test_direct_selects_are_masked(query_engine):
    result = query_engine.execute("SELECT aadhaar, salary FROM customers", "ANALYST")
    assert result["rows"][0]["aadhaar"] != RAW_AADHAAR
    assert result["rows"][0]["salary"] == "REDACTED"


def test_select_star_is_masked(query_engine):
    row = query_engine.execute("SELECT * FROM customers", "ANALYST")["rows"][0]
    assert row["aadhaar"] != RAW_AADHAAR
    assert row["name"] == "REDACTED"
    assert row["department"] == "Engineering"


def test_non_sensitive_queries_still_work(query_engine):
    result = query_engine.execute(
        "SELECT department, COUNT(*) AS total FROM customers "
        "WHERE department = 'Finance' GROUP BY department ORDER BY department LIMIT 5",
        "ANALYST",
    )
    assert result["rows"] == [{"department": "Finance", "total": 1}]


def test_admin_queries_are_not_restricted(query_engine):
    result = query_engine.execute(
        "SELECT aadhaar FROM customers WHERE aadhaar LIKE '2345%' ORDER BY 1", "ADMIN"
    )
    assert result["rows"] == [{"aadhaar": RAW_AADHAAR}]


def test_customer_names_are_masked_for_restricted_roles(query_engine):
    analyst = query_engine.execute("SELECT name FROM customers", "ANALYST")
    assert analyst["rows"][0]["name"] == "REDACTED"
    support = query_engine.execute("SELECT name FROM customers", "SUPPORT")
    assert support["rows"][0]["name"] != "Aarav Mehta"


@pytest.mark.parametrize("column", ["name", "full_name", "customer_first_name"])
def test_person_name_columns_are_detected(column):
    assert PIIDetector().classify_by_column_name(column) is not None


@pytest.mark.parametrize("column", ["filename", "table_name", "hostname"])
def test_generic_name_columns_are_not_flagged(column):
    assert PIIDetector().classify_by_column_name(column) is None


def test_hmac_key_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("VEILDB_HMAC_KEY", "first-key")
    first = HMACMask().apply(RAW_AADHAAR)
    monkeypatch.setenv("VEILDB_HMAC_KEY", "second-key")
    assert HMACMask().apply(RAW_AADHAAR) != first


def test_hmac_does_not_use_the_old_public_key(monkeypatch):
    monkeypatch.delenv("VEILDB_HMAC_KEY", raising=False)
    assert HMACMask().apply(RAW_AADHAAR) != HMACMask("default-secret-key").apply(RAW_AADHAAR)


@pytest.fixture
def client(monkeypatch, query_engine):
    monkeypatch.setattr(api, "query_engine", query_engine)
    monkeypatch.setenv("VEILDB_ADMIN_API_KEY", "admin-test-key")
    monkeypatch.setenv("VEILDB_SUPPORT_API_KEY", "support-test-key")
    monkeypatch.setenv("VEILDB_ANALYST_API_KEY", "analyst-test-key")
    return TestClient(api.app)


QUERY = {"query": "SELECT aadhaar FROM customers"}


def test_query_requires_an_api_key(client):
    assert client.post("/query", json=QUERY).status_code == 401


def test_query_rejects_a_wrong_api_key(client):
    response = client.post("/query", json=QUERY, headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_client_cannot_choose_its_own_role(client):
    response = client.post(
        "/query",
        json={**QUERY, "role": "ADMIN"},
        headers={"X-API-Key": "analyst-test-key"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "ANALYST"
    assert response.json()["rows"][0]["aadhaar"] != RAW_AADHAAR


def test_admin_key_returns_raw_values(client):
    response = client.post("/query", json=QUERY, headers={"X-API-Key": "admin-test-key"})
    assert response.json()["rows"][0]["aadhaar"] == RAW_AADHAAR


def test_no_configured_keys_means_no_access(client, monkeypatch):
    for env_var in api.API_KEY_ENV_VARS.values():
        monkeypatch.delenv(env_var)
    assert client.post("/query", json=QUERY, headers={"X-API-Key": ""}).status_code == 401
