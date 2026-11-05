# SENTINEL AI
## AI Security Testing & Defense Platform

**Discover vulnerabilities. Validate defenses. Protect AI applications.**

**Project status:** Active local security-testing prototype
**Application version:** 0.1.0
**Development environment:** Windows 11 Pro, Python 3.14.10, SQLite
**Deployment:** Localhost-only

---

## 1. Overview

SENTINEL AI is a standalone platform for demonstrating controlled AI application security testing and defense validation.

It combines deterministic security simulations, a centralized security policy engine, authentication and authorization controls, and a web dashboard.

The project is designed as an isolated training and portfolio platform. Its current simulations use synthetic data and mock behavior rather than attacking external AI services or production systems.

## 2. Implemented Capabilities

### AI security simulations

| Identifier | Simulation | Main security objective |
|---|---|---|
| AI-001 | Direct Prompt Injection | Demonstrate direct instruction manipulation and defense validation |
| AI-002 | Indirect Prompt Injection | Demonstrate malicious instructions introduced through untrusted content |
| AI-003 | Agent Tool Misuse | Validate simulated agent-tool permissions and policy enforcement |
| AI-004 | Agent Memory Poisoning | Detect untrusted, manipulated, and tampered memory records |

Each simulation has a corresponding API execution endpoint and frontend integration.

### Central Security Policy Engine

A shared policy engine is integrated with the agent security workflow. It evaluates permitted and denied actions instead of allowing the simulated agent to execute unrestricted tools.

### Authentication and access control

Implemented authentication components include:

- Argon2id password hashing.
- Server-side session management.
- Login throttling and account-state checks.
- Role-based access control (RBAC).
- TOTP multi-factor authentication.
- Recovery-code workflows.
- CSRF and same-origin protections for protected operations.
- Security-conscious HTTP headers.

The initial roles are:

- **Administrator:** platform administration.
- **Security Analyst:** authorized security testing.
- **Auditor:** read-only review permissions.

MFA encryption uses the `SENTINEL_MFA_ENCRYPTION_KEY` environment variable. Keep the same key securely across restarts. Never commit it.

### Web dashboard

The frontend is served by FastAPI from `app/web/`. It provides the local application interface for authentication, approved targets, and the implemented simulations.

### Database

The application uses SQLite. The checked-in schema and migrations represent database versions 1 through 5. The current readiness check expects schema version 5, 19 application tables, and enabled foreign-key enforcement.

## 3. Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| ASGI server | Uvicorn |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Password security | Argon2id |
| MFA | TOTP and encrypted secret storage |
| Cryptography | cryptography package |
| Testing | pytest and FastAPI test client dependencies |
| Version control | Git |

No large local language model is required. The current scenarios use deterministic mock behavior.

## 4. API Endpoints

The following are implemented routes, not the broader planned API specification.

### System

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Application health |
| GET | `/health/ready` | Database readiness |
| GET | `/` | Redirect to the web application |

### Authentication

| Method | Endpoint |
|---|---|
| POST | `/api/v1/auth/login` |
| POST | `/api/v1/auth/mfa/verify` |
| POST | `/api/v1/auth/mfa/enroll` |
| POST | `/api/v1/auth/mfa/enroll/confirm` |
| GET | `/api/v1/auth/me` |
| POST | `/api/v1/auth/logout` |

### Targets

| Method | Endpoint |
|---|---|
| GET | `/api/v1/targets` |
| POST | `/api/v1/targets/initialize` |

### Security simulations

| Method | Endpoint |
|---|---|
| POST | `/api/v1/simulations/AI-001/run` |
| POST | `/api/v1/simulations/AI-002/run` |
| POST | `/api/v1/simulations/AI-003/run` |
| POST | `/api/v1/simulations/AI-004/run` |

FastAPI's interactive API documentation is available at `/docs` when the local server is running.

## 5. Local Development

### Requirements

- Windows 11 or a compatible development environment.
- Python; the current development environment uses Python 3.14.10.
- Git.

### Install dependencies

From the project directory:

```powershell
Set-Location "D:\Cybersecurity-Projects\SENTINEL-AI"
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

### Important database initialization note

The repository contains the base SQLite schema and migrations 002 through 005. However, the current application does not include an automatic first-run database bootstrap or migration runner.

The database connection creates the `data` directory and opens `data/sentinel.db`; it does not create the schema or apply migrations. A fresh checkout therefore needs a correctly initialized schema version 5 database before the complete authenticated application can be used.

Do not treat an empty SQLite file as an initialized database. The readiness endpoint should report `ready`, schema version `5`, 19 tables, and enabled foreign keys.

### Seed roles and permissions

After a correctly initialized database is available:

```powershell
python -m app.db.seed
```

This command seeds RBAC roles and permissions. It does not initialize the database schema or apply migrations.

### Provision an administrator

```powershell
python scripts\create_admin.py
```

The provisioning script prompts for credentials and does not accept the password as a command-line argument. It refuses to create another initial administrator when an active administrator exists.

### Run the application

Keep the server running in its own PowerShell window:

```powershell
Set-Location "D:\Cybersecurity-Projects\SENTINEL-AI"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info
```

Open the dashboard at `http://127.0.0.1:8000/app/`.

Other local endpoints:

- Health: `http://127.0.0.1:8000/health`
- Database readiness: `http://127.0.0.1:8000/health/ready`
- API documentation: `http://127.0.0.1:8000/docs`

The application is configured for localhost access. Do not expose this development instance directly to the public internet.

## 6. Testing

Automated tests are located in `tests/`.

Install development dependencies and run the suite:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Run a focused AI-004 simulation test:

```powershell
python -m pytest tests\test_ai004_memory_poisoning.py -q
```

Report test results only after the command completes successfully in the environment being documented.

## 7. Security Boundaries

SENTINEL AI is an isolated training and demonstration project.

- Use synthetic data only.
- Test only systems you own or are explicitly authorized to assess.
- Current AI simulations use controlled, deterministic mock behavior.
- Agent tools are simulated; no arbitrary host shell execution is exposed.
- Do not enable unrestricted filesystem or network access.
- Do not place credentials, API keys, or encryption keys in Git.
- Keep the application bound to localhost during development.
- Treat audit records and evidence as security-sensitive data.

The HMAC key used in the AI-004 demonstration is illustrative. It is not a production key-management implementation.

## 8. Known Limitations and Planned Work

The following are not currently represented as completed features:

- Arbitrary external AI target integration.
- External model-provider adapters.
- Full RAG security testing.
- AI-005 through AI-012.
- General assessment creation and history workflows.
- Persistent storage of simulation findings and evidence.
- A complete risk-scoring engine.
- MITRE ATLAS mapping.
- PDF assessment report generation.
- A general security-event monitoring interface.
- Automated database bootstrap and migration management.
- Production deployment and production-grade key management.

Although the database contains assessment, test-run, finding, evidence, and security-event tables, the current simulation API is not a complete persistent assessment-management workflow. In particular, the AI-004 simulation records an audit event on a successful run; it does not create a complete persisted assessment, finding, or evidence record.

## 9. Repository Structure

```text
SENTINEL-AI/
â”œâ”€â”€ app/
â”‚   â”œâ”€â”€ api/
â”‚   â”œâ”€â”€ authentication/
â”‚   â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ db/
â”‚   â”‚   â””â”€â”€ migrations/
â”‚   â”œâ”€â”€ web/
â”‚   â””â”€â”€ main.py
â”œâ”€â”€ data/
â”œâ”€â”€ docs/
â”‚   â”œâ”€â”€ API_DESIGN.md
â”‚   â”œâ”€â”€ ARCHITECTURE.md
â”‚   â””â”€â”€ DATABASE_SCHEMA.md
â”œâ”€â”€ scripts/
â”‚   â””â”€â”€ create_admin.py
â”œâ”€â”€ tests/
â”œâ”€â”€ requirements.txt
â”œâ”€â”€ requirements-dev.txt
â””â”€â”€ README.md
```

## 10. Technical Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Design](docs/API_DESIGN.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)

These documents preserve the broader design and identify which parts are implemented and which remain planned.

## 11. Development Principles

- Verify before modifying.
- Back up before changes.
- Keep simulations deterministic and reproducible.
- Keep test data synthetic.
- Apply authorization on the server.
- Avoid unnecessary resource consumption.
- Never describe a planned capability as implemented.