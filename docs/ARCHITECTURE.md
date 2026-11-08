# SENTINEL AI - Technical Architecture

Status: Implemented local portfolio release; deterministic simulation scope and limitations are documented below
Version: 1.0.0

## 1. System Components

1. Analyst Web Interface
2. FastAPI Control Plane
3. Authentication and RBAC
4. Assessment Orchestrator
5. AI Red Team Engine
6. AI Blue Team Engine
7. TestGPT-Vulnerable
8. TestGPT-Secure
9. Deterministic Mock Model
10. SQLite Evidence Store
11. Risk Scoring Engine
12. Reporting Engine

## 2. Data Flow

Analyst
  -> Web Interface
  -> FastAPI
  -> Authentication
  -> Assessment Orchestrator
  -> Red Team Tests
  -> AI Test Targets
  -> Blue Team Controls
  -> Evidence Store
  -> Risk Engine
  -> Reports

## 3. Red Team

The Red Team performs controlled tests:
- Direct and indirect prompt injection
- System prompt disclosure attempts
- Synthetic data leakage
- RAG poisoning and authorization bypass
- Simulated agent tool misuse
- Security regression tests

## 4. Blue Team

The Blue Team provides:
- Input validation
- Output inspection
- Policy enforcement
- Retrieval authorization
- Agent permission checks
- Security event logging
- Risk assessment

## 5. Test Targets

TestGPT-Vulnerable:
- Deliberately insecure training target
- Synthetic data only
- Controlled weaknesses

TestGPT-Secure:
- Security controls enabled
- Authorization enforced
- Input and output validation
- Restricted retrieval and tools

Both targets must remain isolated from production systems.

## 6. Trust Boundaries

TB-01: Browser to API
Authentication, server-side authorization, input validation.

TB-02: API to Assessment Engine
Approved test identifiers, execution limits, timeouts.

TB-03: Assessment Engine to AI Targets
Controlled targets, synthetic data, no host access.

TB-04: AI Targets to Model Adapter
Provider isolation, timeouts, secret protection.

TB-05: RAG Documents to Retrieval Engine
Document ownership, access control, tenant isolation.

TB-06: Application to Evidence Store
Evidence access restrictions, timestamps, SHA-256 integrity checks.

## 7. Agent Security

Initial agent tools are simulated only.

No arbitrary shell execution, unrestricted filesystem access,
unrestricted network access, or autonomous destructive actions.

Sensitive future operations require human approval.

## 8. Data Protection

Use synthetic public, internal, and confidential test data.

Never use real customer data or personal information.

API keys must not be stored in source code.

Raw evidence and generated reports must not be committed to Git.

## 9. Deployment

Initial deployment:
- Windows 11
- Python virtual environment
- FastAPI
- SQLite
- Deterministic mock model
- Localhost-only access

Existing SOC NEXUS, Splunk, n8n, MISP, and TheHive
remain separate and untouched.

## 10. Resource Constraints

- Workstation RAM: 16 GB
- No large local LLM initially
- Lightweight database
- Bounded test execution
- Limited concurrency
- No unnecessary containers or virtual machines

## 11. Acceptance Criteria

- Six trust boundaries documented
- Authorized isolated targets
- Synthetic data only
- Simulated agent tools
- Evidence integrity checks
- Local deployment isolation
- Resource limits documented

## 12. Implementation Status

**Status reviewed: November 8, 2026**

### Implemented and verified in the current release

- FastAPI application entry point, localhost web interface, and health/readiness routes.
- Authentication, Argon2id password hashing, server-side sessions, RBAC, MFA workflows, login throttling, and protected state-changing requests.
- SQLite base schema and versioned migrations through schema version 6, with a database initialization and migration utility.
- Direct prompt-injection simulation (AI-001).
- Indirect prompt-injection simulation (AI-002).
- Agent tool-misuse simulation and policy integration (AI-003).
- Agent memory-poisoning simulation (AI-004).
- Central security policy engine and controlled mock agent tools.
- Permission-gated draft assessment creation for the four registered scenarios.
- Bounded, read-only assessment history with allowlisted metadata.
- Sanitized reports for completed assessments and test runs.
- Audit events for assessment creation and completed simulation executions.

### Important implementation boundaries

The four AI scenarios are deterministic mock simulations. They do not connect to arbitrary external AI models or targets. Agent tools are simulated and do not execute arbitrary host commands or unrestricted external actions.

Draft creation records a draft assessment, queued test runs, and an audit event. It does not execute a simulation. Simulation execution is a separate, permission-gated operation.

Completed fixed-scenario executions persist assessment and test-run records with sanitized execution results and audit events. The current implementation does not create finding or evidence records. The assessment history API returns allowlisted metadata only. The report API constructs a sanitized report for a completed test run; it does not expose raw execution JSON or unrestricted simulation output.

The database initialization utility applies and verifies schema migrations through version 6. The local database should be backed up before any intentional migration or maintenance operation.

### Still planned or outside this release

- External model-provider adapters and arbitrary authorized target integration.
- Full RAG security testing and retrieval authorization workflows.
- Additional AI security scenarios beyond AI-004.
- General-purpose assessment orchestration and arbitrary test-case catalogs.
- Persistent findings and evidence management.
- General risk scoring and MITRE ATLAS mapping.
- PDF export and downloadable PDF reports.
- General security-event monitoring and audit-browsing interfaces.
- Production deployment, production-grade secret management, and operational hardening.

This release is a local training and portfolio demonstration platform. The broader target architecture described elsewhere in this document is not a claim that every planned component has been implemented.
