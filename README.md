# 🛡️ VeilDB

### Schema Inspection and Role-Aware PII Masking for SQL Queries

**Protect sensitive database information with intelligent PII detection, role-based access control, and dynamic data masking.**

---

## 📌 Overview

VeilDB is a database security and privacy solution designed to inspect database schemas, identify Personally Identifiable Information (PII), and enforce role-aware masking policies on SQL query results.

It provides an additional security layer between database users and sensitive information, ensuring that users only access data permitted by their assigned roles.

Instead of exposing sensitive information directly, VeilDB applies configurable masking strategies according to data sensitivity and user permissions.

## 🚨 Problem Statement

Modern applications store large amounts of sensitive information, including:

* Personal names and contact information.
* Email addresses and phone numbers.
* Aadhaar and PAN numbers.
* Credit card and financial information.
* Other confidential customer records.

Traditional database access control often focuses on whether a user can access a table rather than what sensitive information they should see within that table.

This creates several challenges:

* Excessive exposure of sensitive information.
* Inconsistent data protection across user roles.
* Difficulty identifying PII across database schemas.
* Risk of accidental disclosure through SQL queries.
* Limited visibility into data masking decisions.

## 💡 Our Solution

VeilDB introduces role-aware data protection through three major capabilities:

1. **Schema Inspection:** Understand database structures and identify potentially sensitive columns.
2. **PII Detection:** Identify sensitive information using classification and pattern validation.
3. **Dynamic Data Masking:** Apply different masking strategies according to user roles and data sensitivity.

## ✨ Key Features

### 1. Schema Inspection

* Inspect database tables and columns.
* Retrieve column metadata.
* Identify potentially sensitive fields.
* Understand the structure of connected databases.

### 2. PII Detection

Detect and classify sensitive information, including:

* Names
* Email addresses
* Phone numbers
* Aadhaar numbers
* PAN numbers
* Credit card information
* Bank account information

### 3. Role-Based Access Control (RBAC)

VeilDB supports different access levels:

| Role    | Access                               |
| ------- | ------------------------------------ |
| ADMIN   | Full access                          |
| SUPPORT | Access according to support policies |
| ANALYST | Restricted access with masking       |

### 4. Intelligent Data Masking

Different masking strategies can be applied depending on the sensitivity and access policy.

* **HASH:** Transform sensitive values into hashed representations.
* **REDACT:** Hide sensitive values.
* **MASK:** Replace sensitive information with masked representations.
* **PARTIAL MASKING:** Reveal only permitted portions of a value.

### 5. SQL Query Processing

* Accept SQL SELECT queries.
* Process queries through the backend.
* Apply role-aware masking policies.
* Return processed results.

### 6. Interactive Dashboard

The Streamlit dashboard provides an interface for interacting with VeilDB, inspecting database information, and viewing query results.

---

## 🏗️ System Architecture

```text
             USER
               |
               v
       VEILDB DASHBOARD
          (Streamlit)
               |
               v
         FASTAPI BACKEND
               |
        +------+------+
        |             |
        v             v
   Schema         SQL Query
  Inspection      Processing
        |             |
        v             v
   PII Detection  Access Control
        |             |
        +------+------+
               |
               v
        MASKING ENGINE
               |
       Role-Based Policies
               |
               v
       PROCESSED RESULTS
               |
               v
          USER DASHBOARD
```

## ⚙️ Technology Stack

| Component         | Technology                                  |
| ----------------- | ------------------------------------------- |
| Backend           | Python, FastAPI                             |
| Frontend          | Streamlit                                   |
| Database          | SQL database integration                    |
| API Documentation | Swagger / OpenAPI                           |
| Security          | Role-Based Access Control                   |
| PII Detection     | Pattern-based validation and classification |
| Data Protection   | Hashing and masking strategies              |

## 📂 Project Structure

```text
VeilDB/
│
├── backend/
│   └── app/
│       ├── API and backend modules
│       ├── Schema inspection
│       ├── PII detection
│       └── Query processing
│
├── frontend/
│   └── app.py
│
├── tests/
│
├── test_debug.py
├── test_fix.py
├── test_output.txt
│
└── README.md
```

*The backend module breakdown should be updated to match the final repository files.*

---

## 🚀 Getting Started

### Prerequisites

* Python 3.10+
* pip
* Git
* A supported SQL database and its connection configuration

### 1. Clone the Repository

```bash
git clone https://github.com/papnoivaishnavi/VeilDB.git

cd VeilDB
```

### 2. Create a Virtual Environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Install the dependencies specified by the project's backend and frontend requirements files.

```bash
pip install -r requirements.txt
```

*If the repository uses separate requirements files, install each component's dependencies separately.*

### 4. Start the Backend

Start the FastAPI application using its configured Uvicorn entry point.

```bash
uvicorn <backend_module>:app --reload --port 8000
```

### 5. Access API Documentation

Once the backend is running:

```text
http://127.0.0.1:8000/docs
```

### 6. Start the Frontend

```bash
python -m pip install streamlit
python -m streamlit run frontend/app.py
```

Access the dashboard:

```text
http://localhost:8501
```

---

## 🔌 API Endpoints

VeilDB exposes REST API endpoints through FastAPI.

| Method | Endpoint  | Description                     |
| ------ | --------- | ------------------------------- |
| GET    | `/schema` | Inspect database schema         |
| POST   | `/query`  | Execute and process SQL queries |

### GET /schema

Retrieves database schema information, including table and column metadata.

Example:

```bash
curl http://127.0.0.1:8000/schema
```

### POST /query

Processes a SQL query through the VeilDB security and masking pipeline.

Example request:

```json
{
  "query": "SELECT * FROM customers",
  "role": "ANALYST"
}
```

*Adjust request fields to match the actual API schema exposed by Swagger.*

---

## 🔐 Security Model

VeilDB uses role-aware policies to determine how sensitive information should be exposed.

Example policy behavior:

| Data Classification | SUPPORT                  | ANALYST |
| ------------------- | ------------------------ | ------- |
| High PII            | Policy-controlled access | HASH    |
| Medium PII          | Policy-controlled access | REDACT  |
| Financial           | Full access              | REDACT  |
| Needs Review        | Policy-controlled access | REDACT  |

ADMIN has full access under the configured role policy.

### Why Role-Aware Masking?

Different users require different levels of information.

For example:

* An administrator may require complete customer information.
* A support representative may need financial details to resolve a customer issue.
* An analyst may need anonymized information to identify trends without accessing raw personal information.

VeilDB makes this distinction part of the query-processing workflow.

---

## 🧪 Testing

Run the project's test suite using:

```bash
pytest
```

For individual test modules:

```bash
pytest tests/
```

Testing should cover:

* PII detection accuracy.
* Masking strategy correctness.
* Role-based access policies.
* SQL query processing.
* Schema inspection.
* Invalid input handling.
* Sensitive data protection.

---

## 🎯 Use Cases

1. **Financial Applications:** Protect customer financial information.
2. **Healthcare Systems:** Reduce unnecessary exposure of patient information.
3. **Analytics Platforms:** Allow analysts to work with protected datasets.
4. **Enterprise Databases:** Apply role-aware privacy policies.
5. **Customer Support Systems:** Provide access to necessary information without unrestricted exposure.

## 🔮 Future Enhancements

* Automated PII discovery across larger database schemas.
* Support for additional database engines.
* More configurable masking strategies.
* Fine-grained column-level permissions.
* Comprehensive audit logging.
* Policy management through the dashboard.
* Docker-based deployment.
* Integration with enterprise authentication systems.

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Test your implementation.
5. Submit a pull request.

## 👥 Contributors

Developed collaboratively by the VeilDB team.

## 📜 License

Add the project's chosen open-source license here.

---

**VeilDB — Protecting sensitive data without compromising accessibility.**
