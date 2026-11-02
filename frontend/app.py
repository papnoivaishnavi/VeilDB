"""Streamlit interface for inspecting and querying VeilDB."""

from __future__ import annotations

import os

import requests
import streamlit as st


st.set_page_config(page_title="VeilDB", page_icon="🔐", layout="wide")
st.title("VeilDB")
st.caption("Explore a database schema and see sensitive fields masked for each role.")

api_url = os.environ.get("VEILDB_API_URL", "http://127.0.0.1:8000").rstrip("/")
role_descriptions = {
    "ADMIN": "Full access to all classifications.",
    "SUPPORT": "Partial access to personal data; full access to financial data.",
    "ANALYST": "Hashes high sensitivity data and redacts medium and financial data.",
}

with st.sidebar:
    st.header("Access role")
    role = st.selectbox("View results as", ("ADMIN", "SUPPORT", "ANALYST"))
    st.caption(role_descriptions[role])
    st.divider()
    st.caption(f"API: `{api_url}`")

try:
    schema_response = requests.get(f"{api_url}/schema", timeout=15)
    schema_response.raise_for_status()
    schema = schema_response.json()
except requests.RequestException as error:
    schema = None
    st.error(f"Could not load the database schema. Start the API and try again. ({error})")

left, right = st.columns([1, 2])
with left:
    st.subheader("Database schema")
    if schema is not None:
        st.metric("Tables", schema.get("tables_scanned", 0))
        st.metric("Detected sensitive columns", schema.get("pii_columns", 0))
        for table_info in schema.get("results", []):
            with st.expander(table_info["table"], expanded=True):
                columns = [
                    {"Column": name, **details}
                    for name, details in table_info.get("columns", {}).items()
                ]
                st.dataframe(columns, hide_index=True, use_container_width=True)

with right:
    st.subheader("Run a SQL query")
    with st.form("query_form"):
        query = st.text_area(
            "SELECT query",
            value=st.session_state.get(
                "query_text",
                "SELECT id, name, email, phone, aadhaar, credit_card, salary "
                "FROM customers ORDER BY id LIMIT 20",
            ),
            height=140,
            help="Only one read-only SELECT statement is accepted.",
        )
        submitted = st.form_submit_button("Run query", type="primary")

    if submitted:
        st.session_state["query_text"] = query
        try:
            response = requests.post(
                f"{api_url}/query",
                json={"query": query, "role": role},
                timeout=30,
            )
            if response.ok:
                result = response.json()
                st.success(f"Returned {result['row_count']} rows as {result['role']}.")
                st.dataframe(result["rows"], hide_index=True, use_container_width=True)
                st.caption("Masking applied to each result column")
                st.dataframe(result["columns"], hide_index=True, use_container_width=True)
            else:
                try:
                    message = response.json().get("detail", response.text)
                except ValueError:
                    message = response.text
                st.error(f"Query failed: {message}")
        except requests.RequestException as error:
            st.error(f"Could not reach the query API. ({error})")
