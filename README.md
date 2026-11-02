# VeilDB

VeilDB combines schema based PII detection, role policies, and dynamic result
masking with a small FastAPI and Streamlit demo.

## Run locally

```bash
python3 -m pip install -r requirements.txt
python3 -m backend.seed
uvicorn backend.app.api:app --reload
```

In another terminal, from the repository root:

```bash
streamlit run frontend/app.py
```

The API also seeds the bundled SQLite database on first startup. The seed
script is safe to run again; use `python3 -m backend.seed --reset` to replace
the demo `customers` table. All bundled records are fictional.

Set `DATABASE_URL` to a SQLAlchemy database URL before starting the API or seed
script to use another database. The API only accepts one `SELECT` query at a
time. Query requests include the selected demo role, and `/query` returns rows
after applying the matching RBAC policy. The Streamlit process can point to a
different API with `VEILDB_API_URL`.

## API

- `GET /schema` returns table and column metadata with PII classifications.
- `POST /query` accepts `{"query": "SELECT ...", "role": "SUPPORT"}` and
  returns masked rows plus per-column classifications and strategies.

Available roles are `ADMIN`, `SUPPORT`, and `ANALYST`.
