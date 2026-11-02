"""Create the local SQLite demo database with synthetic PII examples.

Run with ``python -m backend.seed``. Set DATABASE_URL to seed another SQLAlchemy
database. All records in this file are fictional demo data.
"""

from __future__ import annotations

import argparse

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, insert, inspect
from sqlalchemy.engine import Engine

from backend.app.database import create_database_engine, get_database_url


metadata = MetaData()
customers = Table(
    "customers",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(100), nullable=False),
    Column("email", String(255), nullable=False),
    Column("phone", String(24)),
    Column("date_of_birth", String(10)),
    Column("aadhaar", String(12)),
    Column("pan", String(10)),
    Column("bank_account", String(18)),
    Column("credit_card", String(19)),
    Column("salary", Float),
    Column("department", String(80)),
)

SAMPLE_CUSTOMERS = [
    {
        "id": 1,
        "name": "Aarav Mehta",
        "email": "aarav.mehta@example.com",
        "phone": "9876543210",
        "date_of_birth": "1990-05-15",
        "aadhaar": "234567890123",
        "pan": "ABCDE1234F",
        "bank_account": "123456789012",
        "credit_card": "4111111111111111",
        "salary": 92000.00,
        "department": "Engineering",
    },
    {
        "id": 2,
        "name": "Diya Nair",
        "email": "diya.nair@example.com",
        "phone": "9123456789",
        "date_of_birth": "1987-11-02",
        "aadhaar": "345678901234",
        "pan": "PANEL0987A",
        "bank_account": "987654321098",
        "credit_card": "5500000000000004",
        "salary": 108500.00,
        "department": "Finance",
    },
    {
        "id": 3,
        "name": "Kabir Shah",
        "email": "kabir.shah@example.com",
        "phone": "9988776655",
        "date_of_birth": "1993-02-24",
        "aadhaar": "456789012345",
        "pan": "QWERT1234Z",
        "bank_account": "123456789876",
        "credit_card": "4012888888881881",
        "salary": 76500.00,
        "department": "Customer Success",
    },
]


def seed_demo_database(engine: Engine, reset: bool = False) -> None:
    """Create the demo table and add sample rows when it is empty."""
    if reset and "customers" in inspect(engine).get_table_names():
        customers.drop(engine)

    metadata.create_all(engine)
    with engine.begin() as connection:
        has_rows = connection.execute(customers.select().limit(1)).first() is not None
        if not has_rows:
            connection.execute(insert(customers), SAMPLE_CUSTOMERS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="drop and recreate the customers table before seeding it",
    )
    args = parser.parse_args()
    engine = create_database_engine(get_database_url())
    seed_demo_database(engine, reset=args.reset)
    print(f"Seeded synthetic customer records in {get_database_url()}")


if __name__ == "__main__":
    main()
