"""Streamlit dashboard for VeilDB's schema and role-aware query API."""

from __future__ import annotations

import html
import inspect
import os
from typing import Any

import requests
import streamlit as st
import pandas as pd

from backend.app.security.rbac import Classification, RBAC, Role


st.set_page_config(
    page_title="VeilDB | Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = os.environ.get("VEILDB_API_URL", "http://127.0.0.1:8000").rstrip("/")
ROLES = tuple(role.value for role in Role if role != Role.UNKNOWN)
NAVIGATION = ("Overview", "Query Workspace", "Schema Explorer", "Security Insights")
_DATAFRAME_SUPPORTS_WIDTH = "width" in inspect.signature(st.dataframe).parameters
SIDEBAR_POLICY_CLASSIFICATIONS = (
    (Classification.PII_HIGH, "PII High"),
    (Classification.PII_MEDIUM, "PII Medium"),
    (Classification.FINANCIAL_CONFIDENTIAL, "Financial"),
)
CLASSIFICATION_STYLES = {
    "PII_HIGH": "high",
    "PII_MEDIUM": "medium",
    "FINANCIAL_CONFIDENTIAL": "financial",
    "NON_SENSITIVE": "neutral",
    "NEEDS_REVIEW": "review",
}
def _escape(value: Any) -> str:
    """Escape dynamic values before embedding them in dashboard HTML."""
    return html.escape(str(value), quote=True)


def _classification_badge(classification: Any) -> str:
    label = str(classification or "NEEDS_REVIEW").upper()
    style = CLASSIFICATION_STYLES.get(label, "review")
    return f'<span class="badge classification {style}">{_escape(label)}</span>'


def _policy_strategy(role_name: str, classification_name: Any) -> str:
    """Resolve a policy through the backend RBAC configuration."""
    try:
        role = RBAC.get_role(role_name)
        classification = RBAC.get_classification(str(classification_name))
        return RBAC.get_masking_policy(role, classification)
    except ValueError:
        return "UNMAPPED"


def _role_policy_summary(role_name: str) -> str:
    policies = (
        f"{classification.value}: {_policy_strategy(role_name, classification.value)}"
        for classification in Classification
        if classification != Classification.NON_SENSITIVE
    )
    return "  ·  ".join(policies)


def _sidebar_policy_badges(role_name: str) -> str:
    """Render a compact role comparison using backend RBAC values."""
    rows = []
    for classification, display_name in SIDEBAR_POLICY_CLASSIFICATIONS:
        role_badges = []
        for candidate_role in ROLES:
            strategy = _policy_strategy(candidate_role, classification.value)
            style = strategy.lower() if strategy in {"FULL", "HASH", "PARTIAL", "REDACT"} else "review"
            active = " active" if candidate_role == role_name else ""
            role_badges.append(
                f'<span class="sidebar-role-policy role-{candidate_role.lower()}{active}">'
                f'<span class="sidebar-role-name">{_escape(candidate_role)}</span>'
                f'<span class="badge strategy {style}">{_escape(strategy.title())}</span></span>'
            )
        rows.append(
            f'<div class="sidebar-policy-row"><span class="sidebar-policy-label">{_escape(display_name)}</span>'
            f'<div class="sidebar-policy-values">{"".join(role_badges)}</div></div>'
        )
    return '<div class="sidebar-policy-list">' + "".join(rows) + "</div>"


def _policy_cell_style(value: Any) -> str:
    styles = {
        "FULL": "background-color: #26384a; color: #d6e5f3; font-weight: 700;",
        "HASH": "background-color: #293b6a; color: #b5caff; font-weight: 700;",
        "PARTIAL": "background-color: #174b48; color: #a0e5d7; font-weight: 700;",
        "REDACT": "background-color: #542f3b; color: #ffc0bd; font-weight: 700;",
        "UNMAPPED": "background-color: #51412d; color: #f2cd91; font-weight: 700;",
        "PII_HIGH": "background-color: #542f3b; color: #ffc0bd; font-weight: 700;",
        "PII_MEDIUM": "background-color: #51412d; color: #f2cd91; font-weight: 700;",
        "FINANCIAL_CONFIDENTIAL": "background-color: #40365f; color: #d0beff; font-weight: 700;",
        "NEEDS_REVIEW": "background-color: #51412d; color: #f2cd91; font-weight: 700;",
    }
    return styles.get(str(value).upper(), "")


def _render_styled_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        st.info("No records are available for this table.")
        return
    frame = pd.DataFrame(rows, columns=columns)
    style_columns = [
        name for name in ("Classification", "Masking Strategy", "ADMIN", "SUPPORT", "ANALYST")
        if name in frame.columns
    ]
    styled_frame = frame.style
    if hasattr(styled_frame, "map"):
        styled_frame = styled_frame.map(_policy_cell_style, subset=style_columns)
    else:  # pandas before 2.1
        styled_frame = styled_frame.applymap(_policy_cell_style, subset=style_columns)
    _show_dataframe(styled_frame, hide_index=True)


def _show_dataframe(data: Any, **kwargs: Any) -> None:
    """Use Streamlit's current width API while retaining support for older releases."""
    if _DATAFRAME_SUPPORTS_WIDTH:
        st.dataframe(data, width="stretch", **kwargs)
    else:
        st.dataframe(data, use_container_width=True, **kwargs)


def _metric_card(label: str, value: Any, detail: str, icon: str, accent: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card {accent}">
          <div class="metric-top"><span>{_escape(label)}</span><span class="metric-icon">{_escape(icon)}</span></div>
          <div class="metric-value">{_escape(value)}</div>
          <div class="metric-detail">{_escape(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _status_badge(connected: bool) -> str:
    label = "Connected" if connected else "Unavailable"
    state = "online" if connected else "offline"
    return (
        f'<span class="connection-badge {state}"><span class="status-dot"></span>'
        f"{label}</span>"
    )


def _load_schema(api_url: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = requests.get(f"{api_url}/schema", timeout=15)
        response.raise_for_status()
        return response.json(), None
    except requests.RequestException as error:
        return None, str(error)
    except ValueError as error:
        return None, f"The schema endpoint returned invalid JSON: {error}"


def _schema_tables(schema: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not schema:
        return []
    tables = schema.get("results", [])
    return tables if isinstance(tables, list) else []


def _schema_columns(table_info: dict[str, Any]) -> dict[str, Any]:
    columns = table_info.get("columns", {})
    return columns if isinstance(columns, dict) else {}


def _count_classifications(schema: dict[str, Any] | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table_info in _schema_tables(schema):
        if not isinstance(table_info, dict):
            continue
        for details in _schema_columns(table_info).values():
            if not isinstance(details, dict):
                continue
            classification = str(details.get("classification", "NEEDS_REVIEW")).upper()
            if classification != "NON_SENSITIVE":
                counts[classification] = counts.get(classification, 0) + 1
    return counts


def _render_schema_table(table_info: dict[str, Any]) -> None:
    rows: list[str] = []
    for name, details in _schema_columns(table_info).items():
        details = details if isinstance(details, dict) else {}
        classification = str(details.get("classification", "NEEDS_REVIEW")).upper()
        sensitive = classification != "NON_SENSITIVE"
        row_class = "sensitive-row" if sensitive else ""
        nullable = "YES" if details.get("nullable", True) else "NO"
        rows.append(
            f"""
            <tr class="{row_class}">
              <td><span class="field-name">{_escape(name)}</span></td>
              <td><span class="type-label">{_escape(details.get('type', '—'))}</span></td>
              <td>{_escape(nullable)}</td>
              <td>{_classification_badge(classification)}</td>
            </tr>
            """
        )

    if not rows:
        st.info("No columns were returned for this table.")
        return

    st.markdown(
        """
        <div class="table-scroll"><table class="veil-table">
          <thead><tr><th>Column</th><th>Data type</th><th>Nullable</th><th>Classification</th></tr></thead>
          <tbody>
        """
        + "".join(rows)
        + "</tbody></table></div>",
        unsafe_allow_html=True,
    )


def _render_sensitive_fields(schema: dict[str, Any] | None, selected_role: str) -> int:
    rows: list[dict[str, Any]] = []
    for table_info in _schema_tables(schema):
        if not isinstance(table_info, dict):
            continue
        table_name = table_info.get("table", "Unknown table")
        for name, details in _schema_columns(table_info).items():
            details = details if isinstance(details, dict) else {}
            classification = str(details.get("classification", "NEEDS_REVIEW")).upper()
            if classification == "NON_SENSITIVE":
                continue
            detected_type = details.get("detected_type", "—")
            confidence_value = details.get("confidence")
            confidence = (
                f"{float(confidence_value):.0%}"
                if isinstance(confidence_value, (int, float))
                else "—"
            )
            reasons = details.get("detection_reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            reason_text = ", ".join(str(reason) for reason in reasons) or "—"
            row: dict[str, Any] = {
                "Column": f"{table_name}.{name}",
                "Classification": classification,
                f"Effective strategy · {selected_role}": _policy_strategy(selected_role, classification),
                "Detected as": detected_type,
                "Confidence": confidence,
                "Detection signals": reason_text,
            }
            for role_name in ROLES:
                row[role_name] = _policy_strategy(role_name, classification)
            rows.append(row)

    if rows:
        columns = [
            "Column",
            "Classification",
            f"Effective strategy · {selected_role}",
            "ADMIN",
            "SUPPORT",
            "ANALYST",
            "Detected as",
            "Confidence",
            "Detection signals",
        ]
        _render_styled_table(rows, columns)
    else:
        st.info("No sensitive fields were reported by the current schema scan.")
    return len(rows)


def _render_masking_policies(columns: list[dict[str, Any]]) -> None:
    if not columns:
        st.info("No column masking metadata was returned for this query.")
        return
    rows: list[dict[str, Any]] = []
    for item in columns:
        item = item if isinstance(item, dict) else {}
        rows.append(
            {
                "Column": item.get("name", "—"),
                "Classification": item.get("classification", "—"),
                "Masking Strategy": item.get("strategy", "—"),
            }
        )
    _render_styled_table(
        rows,
        ["Column", "Classification", "Masking Strategy"],
    )


def _clear_visible_query_result() -> None:
    """Discard all result data and metadata before a request runs."""
    for key in ("last_query_result", "last_query_role", "last_query_text"):
        st.session_state.pop(key, None)


def _execute_query(api_url: str, query: str, role: str, automatic: bool = False) -> None:
    """Call the existing query endpoint and only retain matching-role results."""
    _clear_visible_query_result()
    with st.spinner(f"Executing query and applying {role} masking policy…"):
        try:
            response = requests.post(
                f"{api_url}/query",
                json={"query": query},
                headers={"X-API-Key": os.environ.get(f"VEILDB_{role}_API_KEY", "")},
                timeout=30,
            )
            if not response.ok:
                try:
                    payload = response.json()
                    message = payload.get("detail", response.text) if isinstance(payload, dict) else response.text
                except ValueError:
                    message = response.text
                st.session_state["query_feedback"] = {
                    "kind": "error",
                    "message": f"Query failed: {message}",
                }
                return

            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("The query response must be a JSON object.")
            response_role = str(result["role"]).upper()
            rows = result["rows"]
            columns = result["columns"]
            row_count = result["row_count"]
            if response_role != role:
                raise ValueError("The API response role did not match the selected role.")
            if not isinstance(rows, list) or not isinstance(columns, list):
                raise ValueError("The query response rows or columns have an unexpected shape.")

            st.session_state["last_query_result"] = result
            st.session_state["last_query_role"] = response_role
            st.session_state["last_query_text"] = query
            st.session_state["last_successful_query"] = query
            st.session_state["query_text"] = query
            if automatic:
                message = f"Last successful query refreshed as {response_role}; returned {row_count} rows."
            else:
                message = f"Returned {row_count} rows as {response_role}."
            st.session_state["query_feedback"] = {"kind": "success", "message": message}
        except requests.RequestException as error:
            st.session_state["query_feedback"] = {
                "kind": "error",
                "message": f"Could not reach the query API. ({error})",
            }
        except (KeyError, TypeError, ValueError) as error:
            st.session_state["query_feedback"] = {
                "kind": "error",
                "message": f"The query API returned an unexpected response. ({error})",
            }


def _render_query_workspace(role: str, api_url: str) -> None:
    st.markdown('<div class="eyebrow">QUERY CONSOLE</div>', unsafe_allow_html=True)
    st.subheader("Query Workspace")
    st.caption(
        "Run a read-only SELECT. VeilDB applies the selected role’s masking policy before results are returned."
    )

    with st.form("query_form", clear_on_submit=False):
        query = st.text_area(
            "SQL statement",
            value=st.session_state.get(
                "query_text",
                "SELECT id, name, email, phone, aadhaar, credit_card, salary "
                "FROM customers ORDER BY id LIMIT 20",
            ),
            height=210,
            help="The API accepts one read-only SELECT statement at a time.",
            placeholder="SELECT column_name FROM table_name LIMIT 20",
        )
        submitted = st.form_submit_button("▶  Run query", type="primary", use_container_width=True)

    if submitted:
        st.session_state["query_text"] = query
        _execute_query(api_url, query, role)

    feedback = st.session_state.get("query_feedback")
    if isinstance(feedback, dict):
        if feedback.get("kind") == "success":
            st.success(feedback.get("message", "Query completed."))
        elif feedback.get("kind") == "error":
            st.error(feedback.get("message", "The query could not be completed."))
        elif feedback.get("kind") == "info":
            st.info(feedback.get("message", "No previous query is available to refresh."))

    result = st.session_state.get("last_query_result")
    executed_role = result.get("role") if isinstance(result, dict) else None
    if (
        not isinstance(result, dict)
        or executed_role != role
        or st.session_state.get("last_query_role") != executed_role
    ):
        if isinstance(result, dict):
            _clear_visible_query_result()
        st.markdown(
            '<div class="empty-panel"><div class="empty-icon">⌘</div>'
            '<div class="empty-title">No results for this role yet</div>'
            '<div class="empty-copy">Run a SELECT query to inspect results and the masking decisions applied for the selected role.</div></div>',
            unsafe_allow_html=True,
        )
        return

    executed_role = str(executed_role)
    st.markdown(
        f'<div class="result-heading"><div><div class="eyebrow">LATEST SUCCESSFUL EXECUTION</div>'
        f'<h3>Query results</h3></div><div class="query-execution-banner role-{executed_role.lower()}">'
        f'<span>QUERY EXECUTED AS:</span><strong>{_escape(executed_role)}</strong></div></div>',
        unsafe_allow_html=True,
    )
    saved_query = st.session_state.get("last_query_text", "")
    if saved_query:
        st.code(saved_query, language="sql")

    rows = result["rows"]
    policies = result["columns"]
    count, role_col = st.columns([1, 3])
    count.metric("Rows returned", result["row_count"])
    role_col.caption(f"Effective RBAC policy: { _role_policy_summary(executed_role) }")

    if rows:
        _show_dataframe(rows, hide_index=True)
    else:
        st.info("The query completed successfully and returned no rows.")

    st.markdown('<div class="section-label">MASKING APPLIED BY COLUMN</div>', unsafe_allow_html=True)
    _render_masking_policies(policies)


def _render_overview(schema: dict[str, Any] | None, connected: bool, role: str) -> None:
    st.markdown('<div class="eyebrow">SECURITY OVERVIEW</div>', unsafe_allow_html=True)
    st.subheader("Database posture")
    st.caption("A live view of the connected database schema and VeilDB’s current access context.")

    tables = _schema_tables(schema)
    table_count = schema.get("tables_scanned") if schema and "tables_scanned" in schema else "—"
    pii_count = schema.get("pii_columns") if schema and "pii_columns" in schema else "—"
    columns = st.columns(4)
    with columns[0]:
        _metric_card("Database tables", table_count, "Tables scanned by the API", "▦", "blue")
    with columns[1]:
        _metric_card("Sensitive columns", pii_count, "Detected across scanned tables", "◈", "teal")
    with columns[2]:
        _metric_card("Access roles", len(ROLES), "Configured RBAC roles", "◎", "indigo")
    with columns[3]:
        _metric_card(
            "API connection",
            "Online" if connected else "Offline",
            "Schema endpoint availability",
            "●",
            "green" if connected else "red",
        )

    if not connected:
        st.warning("Live database metrics are unavailable until the VeilDB API responds.")
        return

    left, right = st.columns([1.2, 1])
    with left:
        st.markdown('<div class="section-label">SCHEMA SNAPSHOT</div>', unsafe_allow_html=True)
        st.markdown('<div class="panel-title">Tables in scope</div>', unsafe_allow_html=True)
        if tables:
            for table_info in tables:
                if not isinstance(table_info, dict):
                    continue
                table_name = str(table_info.get("table", "Unknown table"))
                column_count = len(_schema_columns(table_info))
                st.markdown(
                    f'<div class="list-row"><span class="table-glyph">▦</span>'
                    f'<span class="list-primary">{_escape(table_name)}</span>'
                    f'<span class="list-meta">{column_count} columns</span></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("The connected database has no tables to display.")
    with right:
        st.markdown('<div class="section-label">DETECTION SUMMARY</div>', unsafe_allow_html=True)
        st.markdown('<div class="panel-title">Sensitive classifications</div>', unsafe_allow_html=True)
        classification_counts = _count_classifications(schema)
        if classification_counts:
            for classification, count in sorted(classification_counts.items()):
                st.markdown(
                    f'<div class="list-row"><span>{_classification_badge(classification)}</span>'
                    f'<span class="list-meta">{count} fields</span></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No sensitive classifications were reported by the schema scan.")
        st.markdown(
            f'<div class="current-role-card"><span class="role-overline">CURRENT ACCESS CONTEXT</span>'
            f'<strong>{_escape(role)}</strong><span>{_escape(_role_policy_summary(role))}</span></div>',
            unsafe_allow_html=True,
        )


def _render_schema_explorer(schema: dict[str, Any] | None, connected: bool) -> None:
    st.markdown('<div class="eyebrow">DATABASE CATALOG</div>', unsafe_allow_html=True)
    st.subheader("Schema Explorer")
    st.caption("Column metadata and sensitivity classifications from the live schema scan.")
    if not connected:
        st.info("Schema details will appear when the API is available.")
        return

    tables = _schema_tables(schema)
    if not tables:
        st.info("The connected database does not contain any tables or views.")
        return
    for table_info in tables:
        if not isinstance(table_info, dict):
            continue
        table_name = str(table_info.get("table", "Unknown table"))
        columns = _schema_columns(table_info)
        sensitive_count = sum(
            1
            for details in columns.values()
            if isinstance(details, dict)
            and str(details.get("classification", "NON_SENSITIVE")).upper() != "NON_SENSITIVE"
        )
        title = f"▦  {table_name}  ·  {len(columns)} columns  ·  {sensitive_count} sensitive"
        with st.expander(title, expanded=len(tables) == 1):
            _render_schema_table(table_info)


def _render_security_insights(schema: dict[str, Any] | None, connected: bool, selected_role: str) -> None:
    st.markdown('<div class="eyebrow">DETECTION & POLICY</div>', unsafe_allow_html=True)
    st.subheader("Security Insights")
    st.caption("Separate intrinsic PII classifications from the effective strategy selected by backend RBAC.")
    if not connected:
        st.info("Security insights will appear when the API is available.")
        return

    st.markdown(
        f'<div class="current-role-card role-{selected_role.lower()}"><span class="role-overline">CURRENTLY SELECTED ACCESS ROLE</span>'
        f'<strong>{_escape(selected_role)}</strong>'
        f'<span>{_escape(_role_policy_summary(selected_role))}</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="section-label">SENSITIVE FIELD POLICY COMPARISON</div>', unsafe_allow_html=True)
    st.caption(
        f"Classification is reported by the live schema scan. Effective strategy for {selected_role} and the role comparison are resolved from backend RBAC configuration."
    )
    field_count = _render_sensitive_fields(schema, selected_role)
    st.markdown('<div class="section-label">ROLE-BASED MASKING</div>', unsafe_allow_html=True)
    st.markdown('<div class="panel-title">Configured strategy by classification</div>', unsafe_allow_html=True)
    role_columns = st.columns(3)
    for container, role_name in zip(role_columns, ROLES):
        with container:
            st.markdown(
                f'<div class="role-card role-{role_name.lower()}"><span class="role-card-name">{_escape(role_name)}</span>'
                f'<span class="role-card-copy">{_escape(_role_policy_summary(role_name))}</span></div>',
                unsafe_allow_html=True,
            )

    result = st.session_state.get("last_query_result")
    result_role = st.session_state.get("last_query_role")
    if isinstance(result, dict) and result_role == selected_role:
        executed_role = str(result_role)
        st.markdown('<div class="section-label">OBSERVED QUERY POLICY</div>', unsafe_allow_html=True)
        st.caption(f"Actual per-column metadata returned by the API for the latest query executed as {executed_role}.")
        policies = result.get("columns", [])
        if isinstance(policies, list):
            _render_masking_policies(policies)
    elif field_count:
        st.info(f"Run a query as {selected_role} to see the API's actual per-column result metadata for this role.")


st.markdown(
    """
    <style>
      :root { color-scheme: dark; }
      .stApp, [data-testid="stAppViewContainer"] {
        background: radial-gradient(ellipse at 14% -8%, rgba(30, 64, 120, .20), transparent 38%),
                    radial-gradient(ellipse at 92% 6%, rgba(20, 125, 132, .10), transparent 28%), #080d18;
        color: #e7edf7;
      }
      [data-testid="stHeader"] { background: rgba(8, 13, 24, .84); }
      [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1422 0%, #0a101b 100%);
        border-right: 1px solid rgba(124, 151, 190, .13);
      }
      [data-testid="stSidebar"] > div:first-child { padding-top: 1.2rem; }
      .block-container { max-width: 1500px; padding-top: 1.55rem; padding-bottom: 3rem; }
      h1, h2, h3 { color: #f2f6fc; letter-spacing: -.025em; }
      h1 { font-size: 2.05rem; }
      h2, h3 { margin-bottom: .35rem; }
      p, label, [data-testid="stCaptionContainer"] { color: #9eacc1; }
      [data-testid="stMarkdownContainer"] a { color: #65c9dc; }
      [data-testid="stMetric"] {
        background: #101927; border: 1px solid rgba(143, 165, 194, .14);
        border-radius: 15px; padding: 1rem 1.1rem;
      }
      [data-testid="stMetricLabel"] { color: #91a1b8; }
      [data-testid="stMetricValue"] { color: #f1f6fd; }
      [data-testid="stDataFrame"] { border: 1px solid rgba(143, 165, 194, .16); border-radius: 12px; }
      [data-testid="stExpander"] { background: rgba(16, 25, 39, .76); border: 1px solid rgba(143, 165, 194, .15); border-radius: 13px; }
      [data-testid="stForm"] { background: #0e1725; border: 1px solid rgba(130, 155, 188, .17); border-radius: 16px; padding: 1rem; }
      textarea {
        background: #09111d !important; color: #dce8f7 !important;
        border: 1px solid rgba(112, 145, 187, .32) !important; border-radius: 11px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important;
        line-height: 1.6 !important;
      }
      input, [data-baseweb="select"] > div { background-color: #101927 !important; }
      .stButton > button, [data-testid="stFormSubmitButton"] > button {
        min-height: 2.65rem; border-radius: 10px; border: 1px solid #286c94;
        background: linear-gradient(105deg, #12658c, #3157a4); color: white; font-weight: 650;
        transition: filter .15s ease, transform .15s ease;
      }
      .stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover { filter: brightness(1.12); border-color: #58b9d4; }
      hr { border-color: rgba(124, 151, 190, .16); }
      .brand { display:flex; align-items:center; gap:.72rem; padding:.25rem .15rem 1rem; }
      .brand-shield { display:grid; place-items:center; width:2.35rem; height:2.35rem; border-radius:.8rem; background:linear-gradient(145deg,#123b62,#214384); color:#84d7e7; font-size:1.1rem; box-shadow:0 5px 18px rgba(18,89,128,.22); }
      .brand-name { color:#f3f7fc; font-size:1.22rem; font-weight:750; letter-spacing:.015em; }
      .brand-tag { color:#7890ac; font-size:.67rem; letter-spacing:.14em; margin-top:.08rem; }
      .eyebrow, .section-label { color:#66b8d0; font-size:.68rem; font-weight:750; letter-spacing:.13em; margin:.4rem 0 .45rem; }
      .section-label { margin-top:1.45rem; }
      .topbar { display:flex; align-items:center; justify-content:space-between; gap:1rem; padding:0 0 1rem; border-bottom:1px solid rgba(126,153,190,.14); margin-bottom:1.55rem; }
      .topbar-title { color:#f5f8fd; font-size:1.38rem; line-height:1.25; font-weight:740; }
      .topbar-subtitle { color:#8292a9; font-size:.84rem; margin-top:.27rem; }
      .topbar-right { display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; justify-content:flex-end; }
      .connection-badge, .role-pill { display:inline-flex; align-items:center; gap:.5rem; color:#b7c4d6; background:#101a29; border:1px solid rgba(139,163,195,.18); border-radius:999px; padding:.45rem .72rem; font-size:.76rem; white-space:nowrap; }
      .connection-badge.online { color:#8fe0c4; border-color:rgba(75,191,151,.25); }
      .connection-badge.offline { color:#f1a7a7; border-color:rgba(224,112,112,.25); }
      .status-dot { width:.47rem; height:.47rem; border-radius:50%; background:#53d2a6; box-shadow:0 0 9px rgba(83,210,166,.42); }
      .offline .status-dot { background:#ed7777; box-shadow:0 0 9px rgba(237,119,119,.3); }
      .sidebar-policy-list { margin:.25rem 0 .55rem; padding:.2rem .62rem; border:1px solid rgba(133,158,191,.14); border-radius:10px; background:rgba(16,25,39,.7); }
      .sidebar-policy-row { display:flex; flex-direction:column; gap:.34rem; padding:.48rem 0; border-bottom:1px solid rgba(133,158,191,.09); }
      .sidebar-policy-row:last-child { border-bottom:0; }
      .sidebar-policy-label { color:#aab9cc; font-size:.7rem; font-weight:650; }
      .sidebar-policy-values { display:flex; flex-wrap:wrap; gap:.25rem; }
      .sidebar-role-policy { display:inline-flex; align-items:center; gap:.28rem; padding:.17rem .24rem; border:1px solid rgba(133,158,191,.12); border-radius:7px; background:rgba(7,13,23,.45); }
      .sidebar-role-policy.active { border-color:rgba(111,182,217,.52); background:rgba(31,75,105,.3); }
      .sidebar-role-name { color:#8296af; font-size:.56rem; font-weight:700; letter-spacing:.025em; }
      .sidebar-role-policy.active .sidebar-role-name { color:#d2e9f2; }
      .sidebar-role-policy .badge { padding:.17rem .34rem; font-size:.59rem; }
      .query-execution-banner { display:flex; align-items:center; gap:.65rem; padding:.62rem .86rem; border:1px solid rgba(109,159,212,.28); border-radius:11px; background:linear-gradient(110deg,rgba(34,67,110,.56),rgba(22,34,55,.9)); }
      .query-execution-banner > span { color:#9eb3cf; font-size:.68rem; font-weight:750; letter-spacing:.10em; }
      .query-execution-banner > strong { color:#f1f6fd; font-size:.95rem; letter-spacing:.045em; }
      .query-execution-banner.role-admin { border-color:rgba(110,159,232,.42); }
      .query-execution-banner.role-support { border-color:rgba(82,200,181,.42); }
      .query-execution-banner.role-analyst { border-color:rgba(162,139,233,.46); }
      .metric-card { min-height:139px; padding:1.05rem 1.1rem .95rem; border-radius:15px; border:1px solid rgba(143,165,194,.15); background:linear-gradient(145deg,#111c2b,#0d1623); margin-bottom:.6rem; }
      .metric-card.blue { box-shadow:inset 0 2px 0 rgba(68,153,219,.55); }
      .metric-card.teal { box-shadow:inset 0 2px 0 rgba(63,199,181,.55); }
      .metric-card.indigo { box-shadow:inset 0 2px 0 rgba(125,126,239,.55); }
      .metric-card.green { box-shadow:inset 0 2px 0 rgba(70,197,148,.55); }
      .metric-card.red { box-shadow:inset 0 2px 0 rgba(220,108,108,.55); }
      .metric-top { display:flex; justify-content:space-between; align-items:center; color:#94a5bb; font-size:.78rem; }
      .metric-icon { color:#74c7d9; font-size:1.05rem; }
      .metric-value { color:#f2f6fc; font-size:1.75rem; line-height:1.35; font-weight:720; margin-top:.58rem; }
      .metric-detail { color:#73869e; font-size:.72rem; margin-top:.15rem; }
      .table-scroll { overflow-x:auto; width:100%; border:1px solid rgba(133,158,191,.15); border-radius:12px; background:#0d1623; }
      table.veil-table { border-collapse:collapse; width:100%; min-width:720px; font-size:.83rem; }
      .veil-table th { color:#7f93ad; text-align:left; font-size:.69rem; letter-spacing:.08em; font-weight:700; text-transform:uppercase; padding:.82rem .9rem; background:#101b2a; border-bottom:1px solid rgba(133,158,191,.17); }
      .veil-table td { color:#c1ccda; padding:.72rem .9rem; border-bottom:1px solid rgba(133,158,191,.10); vertical-align:middle; }
      .veil-table tr:last-child td { border-bottom:0; }
      .veil-table tr.sensitive-row td:first-child { box-shadow:inset 2px 0 #37a9bd; }
      .field-name { color:#dce7f5; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.79rem; }
      .type-label { color:#93a6bd; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.77rem; }
      .reason-cell { color:#91a1b7 !important; }
      .badge { display:inline-flex; align-items:center; border:1px solid transparent; border-radius:999px; padding:.25rem .52rem; white-space:nowrap; font-size:.66rem; font-weight:740; letter-spacing:.035em; }
      .classification.high { color:#ff9f9f; background:rgba(177,55,76,.16); border-color:rgba(231,99,123,.25); }
      .classification.medium { color:#ffd08e; background:rgba(161,103,26,.16); border-color:rgba(231,168,74,.25); }
      .classification.financial { color:#c2aaff; background:rgba(111,75,183,.17); border-color:rgba(160,126,233,.27); }
      .classification.neutral { color:#a8bacd; background:rgba(104,129,155,.13); border-color:rgba(129,151,174,.2); }
      .classification.review, .strategy.review { color:#f0bd76; background:rgba(164,108,34,.16); border-color:rgba(220,157,76,.27); }
      .strategy.hash { color:#9bb9ff; background:rgba(67,104,192,.18); border-color:rgba(108,143,222,.28); }
      .strategy.redact { color:#ffaaa5; background:rgba(178,61,73,.17); border-color:rgba(222,105,112,.28); }
      .strategy.partial { color:#8fe0cf; background:rgba(30,135,119,.16); border-color:rgba(70,190,166,.28); }
      .strategy.full { color:#b8c5d4; background:rgba(106,127,151,.14); border-color:rgba(143,163,186,.22); }
      .list-row { display:flex; align-items:center; gap:.65rem; min-height:2.65rem; padding:.42rem .12rem; border-bottom:1px solid rgba(133,158,191,.10); }
      .table-glyph { color:#55b5ca; font-size:.9rem; }
      .list-primary { color:#d6e0ec; font-size:.84rem; flex:1; }
      .list-meta { color:#788ba3; font-size:.75rem; }
      .panel-title { color:#dbe5f1; font-size:1.04rem; font-weight:650; margin:.1rem 0 .65rem; }
      .current-role-card, .role-card { display:flex; flex-direction:column; gap:.32rem; border:1px solid rgba(104,142,191,.19); background:linear-gradient(145deg,rgba(29,51,81,.4),rgba(15,25,40,.9)); border-radius:12px; padding:.82rem .9rem; margin-top:.8rem; }
      .role-admin { box-shadow:inset 2px 0 #6e9fe8; }
      .role-support { box-shadow:inset 2px 0 #52c8b5; }
      .role-analyst { box-shadow:inset 2px 0 #a28be9; }
      .role-overline { color:#71bad0; font-size:.63rem; font-weight:740; letter-spacing:.12em; }
      .current-role-card strong, .role-card-name { color:#e7eef8; font-size:.88rem; }
      .current-role-card span:last-child, .role-card-copy { color:#8798ae; font-size:.74rem; line-height:1.45; }
      .result-heading { display:flex; align-items:center; justify-content:space-between; gap:1rem; margin-top:1.6rem; }
      .result-heading h3 { margin:0; }
      .result-role { color:#8497ae; font-size:.78rem; }
      .result-role strong { color:#bdcce0; }
      .empty-panel { border:1px dashed rgba(119,151,190,.27); border-radius:15px; background:rgba(14,23,37,.55); text-align:center; padding:2.35rem 1rem; margin-top:1rem; }
      .empty-icon { color:#63b9ce; font-size:1.5rem; margin-bottom:.45rem; }
      .empty-title { color:#dce6f2; font-weight:650; }
      .empty-copy { color:#8192a8; font-size:.82rem; margin-top:.32rem; }
      @media (max-width: 800px) {
        .block-container { padding-left:1rem; padding-right:1rem; }
        .topbar { align-items:flex-start; flex-direction:column; }
        .topbar-right { justify-content:flex-start; }
        .result-heading { align-items:flex-start; flex-direction:column; }
        .metric-card { min-height:125px; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)

selected_role = st.session_state.get("role_selector", ROLES[0])
previous_role = st.session_state.get("last_selected_role")
if previous_role is None:
    # Migrate the prior dashboard's successful result state across an app update.
    previous_role = st.session_state.get("last_query_role", selected_role)
    if "last_successful_query" not in st.session_state:
        previous_query = st.session_state.get("last_query_text")
        if previous_query:
            st.session_state["last_successful_query"] = previous_query
    st.session_state["last_selected_role"] = previous_role

if selected_role != previous_role:
    # Record the new role before the request so a rerun cannot issue it twice.
    st.session_state["last_selected_role"] = selected_role
    _clear_visible_query_result()
    previous_query = st.session_state.get("last_successful_query")
    if isinstance(previous_query, str) and previous_query.strip():
        _execute_query(API_URL, previous_query, selected_role, automatic=True)
    else:
        st.session_state["query_feedback"] = {
            "kind": "info",
            "message": "Role updated. Run a query once to enable automatic refresh when the role changes.",
        }

role = st.session_state.get("role_selector", ROLES[0])
schema, schema_error = _load_schema(API_URL)
connected = schema is not None

with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="brand-shield">⛨</div><div>'
        '<div class="brand-name">VeilDB</div><div class="brand-tag">SECURITY CONSOLE</div>'
        "</div></div>",
        unsafe_allow_html=True,
    )
    st.markdown('<div class="section-label">NAVIGATION</div>', unsafe_allow_html=True)
    page = st.radio("Dashboard section", NAVIGATION, label_visibility="collapsed", key="navigation")

    st.divider()
    st.markdown('<div class="section-label">ACCESS CONTEXT</div>', unsafe_allow_html=True)
    role = st.selectbox("View as role", ROLES, key="role_selector")
    st.markdown(_sidebar_policy_badges(role), unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="section-label">DATABASE CONNECTION</div>', unsafe_allow_html=True)
    st.markdown(_status_badge(connected), unsafe_allow_html=True)
    st.caption(f"API endpoint  ·  `{API_URL}`")
    if schema_error:
        st.caption("Schema request failed. Check that the API is running.")

st.markdown(
    f'<div class="topbar"><div><div class="topbar-title">VeilDB</div>'
    '<div class="topbar-subtitle">Database Security &amp; Privacy Platform</div></div>'
    f'<div class="topbar-right">{_status_badge(connected)}'
    f'<span class="role-pill">Role&nbsp; <strong>{_escape(role)}</strong></span></div></div>',
    unsafe_allow_html=True,
)

if page == "Overview":
    _render_overview(schema, connected, role)
elif page == "Query Workspace":
    _render_query_workspace(role, API_URL)
elif page == "Schema Explorer":
    _render_schema_explorer(schema, connected)
elif page == "Security Insights":
    _render_security_insights(schema, connected, role)
