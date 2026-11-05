# SENTINEL AI - Technical Architecture

Status: Partially implemented prototype; see implementation status
Version: 0.1

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

**Status reviewed: 2026-11-05**

### Implemented and verified in the current prototype

- FastAPI application entry point and localhost web interface.
- Authentication, password security, sessions, RBAC, and MFA workflows.
- SQLite base schema and migrations through version 5.
- Direct prompt-injection simulation (AI-001).
- Indirect prompt-injection simulation (AI-002).
- Agent tool-misuse simulation and policy integration (AI-003).
- Agent memory-poisoning simulation (AI-004).
- Central security policy engine.
- Controlled API routes and frontend dashboard integration.
- Six trust boundaries remain the architectural security model.

### Important implementation boundaries

The current AI targets are deterministic mock simulations. The implemented agent tools do not execute real host commands or perform unrestricted external actions.

The simulation endpoints are fixed scenarios, not general-purpose testing of arbitrary external AI systems. The presence of assessment, test-run, finding, and evidence tables does not mean that the complete assessment persistence and reporting workflow is implemented.

The repository contains the schema and incremental SQL migrations, but does not currently contain an automated database bootstrap or migration runner. The local database must be initialized separately.

### Still planned

- External model adapters and arbitrary authorized target integration.
- Full RAG security testing and retrieval authorization workflows.
- Additional AI security scenarios beyond AI-004.
- Full assessment orchestration and persistent result workflows.
- Risk scoring and framework mapping.
- Complete evidence management and report generation.
- Production deployment, secret management, and operational hardening.

This section describes the implemented prototype. The other sections in this document continue to describe the broader target architecture.
