# SENTINEL AI
## AI Security Testing & Defense Platform

**Tagline:** Discover vulnerabilities. Validate defenses. Protect AI applications.

## 1. Project Overview

SENTINEL AI is a standalone AI application security assessment
platform. It provides controlled security testing, defense
validation, evidence collection, and risk reporting.

The platform has two principal capabilities:

- AI Red Team: perform authorized, repeatable security tests.
- AI Blue Team: detect insecure behavior, evaluate defenses,
  and document findings.

## 2. Project Objectives

1. Identify common AI application security weaknesses.
2. Test prompt injection and data leakage.
3. Assess Retrieval-Augmented Generation (RAG) security.
4. Evaluate AI agent permissions and tool boundaries.
5. Validate input/output security controls.
6. Monitor AI security events.
7. Calculate evidence-based risk scores.
8. Map findings to recognized AI security frameworks.
9. Preserve assessment evidence and generate reports.
10. Compare vulnerable and secured application configurations.

## 3. Initial Architecture

- Frontend: HTML, HTMX, and CSS.
- API: Python and FastAPI.
- Storage: SQLite.
- Testing: Promptfoo and a custom Python test harness.
- AI target: deterministic mock model initially.
- RAG: lightweight local retrieval.
- Security: validation, authorization, and policy enforcement.
- Evidence: structured records and SHA-256 integrity hashes.
- Reporting: PDF assessment reports.

Large local language models are not required for the initial release.

## 4. Main Components

1. Prompt Injection Laboratory
2. Data Leakage Detection
3. RAG Security Laboratory
4. AI Agent Security
5. AI Guardrails
6. AI Identity and Access Control
7. AI Supply Chain Security
8. AI Security Monitoring
9. Risk Scoring Engine
10. MITRE ATLAS Mapping
11. Security Assessment Engine
12. Forensic Evidence and Reporting

## 5. Testing Targets

- TestGPT-Vulnerable: deliberately insecure training target.
- TestGPT-Secure: target with security controls enabled.

Both targets must use synthetic data and controlled test scenarios.

## 6. Security Boundaries

- Test only owned systems or explicitly authorized targets.
- Use synthetic data only.
- Do not expose host shell execution to AI agents.
- Do not provide unrestricted filesystem or network access.
- Simulate sensitive agent tools during initial development.
- Require human approval for sensitive operations.
- Protect credentials and API keys using environment variables.
- Apply rate limits, resource limits, and timeouts.
- Preserve evidence and record test outcomes.

## 7. Development Principles

- One implementation step at a time.
- Read-only checks before changes.
- Verify every important change.
- Back up existing files before modifying them.
- Keep resource consumption low.
- Avoid unnecessary service restarts.
- Do not claim a feature works until tested.

## 8. Development Environment

- OS: Windows 11 Pro, 64-bit.
- Python: 3.14.10.
- Git: 2.56.0.windows.4.
- Python environment: .venv.
- Database: SQLite.
- Project directory: D:\Cybersecurity-Projects\SENTINEL-AI.

## 9. Development Roadmap

The planned development cycle is 12 weeks:

1. Project foundation and threat modeling.
2. API foundation and authentication.
3. Vulnerable AI target.
4. Model adapter.
5. Red Team testing engine.
6. RAG security.
7. Agent security.
8. Blue Team defenses.
9. Risk scoring and framework mapping.
10. Frontend and assessment history.
11. Validation and regression testing.
12. Documentation and portfolio release.

## 10. Current Status

Phase: Project initialization.

Verified:
- Python installed and working.
- pip installed and working.
- Git installed and working.
- Project directory created.
- Isolated Python virtual environment verified.
- Git repository initialized.
- .gitignore created and virtual environment excluded.

Not yet implemented:
- FastAPI application.
- Authentication.
- AI testing targets.
- Red Team and Blue Team engines.
- Database schema.
- Frontend.
- Assessment reports.

This README describes the intended design, not implemented capabilities.
