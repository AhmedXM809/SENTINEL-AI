# SENTINEL AI - Database Schema

Version: 0.1
Status: Partially implemented; see current implementation status
Database: SQLite

## 1. Design Principles

- Use relational tables and foreign keys.
- Enable SQLite foreign-key enforcement.
- Store timestamps consistently in UTC.
- Use unique identifiers for records.
- Use synthetic data exclusively.
- Never store plaintext passwords.
- Never store API secrets in the database.
- Keep raw evidence outside the Git repository.
- Use parameterized SQL queries.
- Apply database migrations for future schema changes.

## 2. Identity and Access Tables

### users
- id: TEXT PRIMARY KEY
- username: TEXT UNIQUE NOT NULL
- email: TEXT UNIQUE
- password_hash: TEXT NOT NULL
- is_active: INTEGER NOT NULL DEFAULT 1
- created_at: TEXT NOT NULL
- updated_at: TEXT NOT NULL

### roles
- id: TEXT PRIMARY KEY
- name: TEXT UNIQUE NOT NULL
- description: TEXT

Initial roles:
- administrator
- security_analyst
- auditor

### permissions
- id: TEXT PRIMARY KEY
- name: TEXT UNIQUE NOT NULL
- description: TEXT

### user_roles
- user_id: TEXT REFERENCES users(id)
- role_id: TEXT REFERENCES roles(id)
- PRIMARY KEY (user_id, role_id)

### role_permissions
- role_id: TEXT REFERENCES roles(id)
- permission_id: TEXT REFERENCES permissions(id)
- PRIMARY KEY (role_id, permission_id)

### user_sessions
- id: TEXT PRIMARY KEY
- user_id: TEXT REFERENCES users(id)
- token_hash: TEXT UNIQUE NOT NULL
- created_at: TEXT NOT NULL
- expires_at: TEXT NOT NULL
- revoked_at: TEXT

Session tokens must be random and securely generated.
Only token hashes are stored in the database.

## 3. AI Target Tables

### target_profiles
- id: TEXT PRIMARY KEY
- name: TEXT NOT NULL
- target_type: TEXT NOT NULL
- security_mode: TEXT NOT NULL
- is_enabled: INTEGER NOT NULL DEFAULT 0
- created_at: TEXT NOT NULL

Initial target types:
- vulnerable
- secure

### model_profiles
- id: TEXT PRIMARY KEY
- name: TEXT NOT NULL
- provider_type: TEXT NOT NULL
- model_identifier: TEXT
- configuration_json: TEXT
- created_at: TEXT NOT NULL

Never store API keys or plaintext credentials here.
Initial provider: deterministic mock model.

## 4. Assessment Tables

### test_cases
- id: TEXT PRIMARY KEY
- scenario_code: TEXT UNIQUE NOT NULL
- name: TEXT NOT NULL
- category: TEXT NOT NULL
- objective: TEXT NOT NULL
- expected_behavior: TEXT NOT NULL
- severity_default: TEXT
- framework_mapping_json: TEXT
- is_enabled: INTEGER NOT NULL DEFAULT 1
- version: TEXT NOT NULL

Scenario codes: AI-001 through AI-012.

### assessments
- id: TEXT PRIMARY KEY
- name: TEXT NOT NULL
- created_by: TEXT REFERENCES users(id)
- target_profile_id: TEXT REFERENCES target_profiles(id)
- model_profile_id: TEXT REFERENCES model_profiles(id)
- status: TEXT NOT NULL
- created_at: TEXT NOT NULL
- started_at: TEXT
- completed_at: TEXT

### test_runs
- id: TEXT PRIMARY KEY
- assessment_id: TEXT REFERENCES assessments(id)
- test_case_id: TEXT REFERENCES test_cases(id)
- status: TEXT NOT NULL
- started_at: TEXT
- completed_at: TEXT
- execution_result: TEXT
- error_summary: TEXT

Each test run represents one execution of one test case.

## 5. Findings and Evidence

### findings
- id: TEXT PRIMARY KEY
- test_run_id: TEXT REFERENCES test_runs(id)
- title: TEXT NOT NULL
- description: TEXT NOT NULL
- severity: TEXT NOT NULL
- confidence: TEXT NOT NULL
- risk_score: REAL
- status: TEXT NOT NULL
- mitigation: TEXT
- created_at: TEXT NOT NULL

Severity values:
- critical
- high
- medium
- low
- informational

### evidence
- id: TEXT PRIMARY KEY
- test_run_id: TEXT REFERENCES test_runs(id)
- finding_id: TEXT REFERENCES findings(id)
- evidence_type: TEXT NOT NULL
- storage_path: TEXT NOT NULL
- sha256: TEXT NOT NULL
- content_size: INTEGER
- classification: TEXT NOT NULL
- collected_at: TEXT NOT NULL

Store evidence metadata in SQLite.
Store raw evidence separately with restricted access.
Never commit raw evidence to Git.

SHA-256 verifies content integrity, not authenticity
or immutability.

## 6. Monitoring and Audit

### security_events
- id: TEXT PRIMARY KEY
- assessment_id: TEXT REFERENCES assessments(id)
- test_run_id: TEXT REFERENCES test_runs(id)
- event_type: TEXT NOT NULL
- severity: TEXT NOT NULL
- description: TEXT NOT NULL
- created_at: TEXT NOT NULL

### audit_log
- id: TEXT PRIMARY KEY
- user_id: TEXT REFERENCES users(id)
- action: TEXT NOT NULL
- resource_type: TEXT NOT NULL
- resource_id: TEXT
- outcome: TEXT NOT NULL
- created_at: TEXT NOT NULL

Audit entries should be append-only through application
permissions and controls. SQLite alone does not guarantee
tamper-proof audit storage.

## 7. Relationships

- Users have roles through user_roles.
- Roles have permissions through role_permissions.
- Users can own multiple sessions.
- Assessments reference one target and one model profile.
- Each assessment contains multiple test runs.
- Each test run references one test case.
- Test runs may produce multiple findings.
- Test runs may produce multiple evidence records.
- Findings may reference supporting evidence.
- Security events may reference assessments and test runs.
- Audit records identify the user and action where available.

## 8. Required Database Controls

- Enable PRAGMA foreign_keys = ON for every connection.
- Use transactions for related writes.
- Use parameterized queries.
- Add indexes for frequently searched foreign keys.
- Validate status and severity values in application code
  and database constraints where appropriate.
- Use explicit cascade policies.
- Avoid cascading deletion of evidence and audit records.
- Restrict database file access.

## 9. Initial Index Plan

- users.username
- users.email
- user_sessions.user_id
- assessments.created_by
- assessments.status
- test_runs.assessment_id
- test_runs.test_case_id
- findings.test_run_id
- findings.severity
- evidence.test_run_id
- evidence.finding_id
- security_events.created_at
- audit_log.created_at

## 10. Retention and Data Protection

- Synthetic data only.
- No real personal or customer records.
- No plaintext credentials.
- No API keys in SQLite.
- Raw evidence stored outside Git.
- Access to confidential synthetic evidence restricted.
- Evidence deletion must follow a documented retention policy.

## 11. Implementation Acceptance Criteria

Before this design becomes a working database:

1. Review and approve all relationships.
2. Define allowed values and validation rules.
3. Define deletion and retention policies.
4. Test foreign-key enforcement.
5. Test transaction rollback.
6. Test unauthorized access.
7. Verify evidence hashing.
8. Back up the database before migrations.

## 12. Current Implementation Status

**Status reviewed: 2026-11-05**

The SQLite database implementation has progressed beyond the original version 0.1 proposal.

### Schema and migration history

- **Version 1:** `app/db/schema.sql` defines the 15 base application tables and their initial indexes.
- **Version 2:** `002_session_idle_timeout.sql`.
- **Version 3:** `003_http_auth_security.sql` adds login-attempt storage required by HTTP authentication protections.
- **Version 4:** `004_login_identifier_throttling.sql` adds the login-identifier throttling index.
- **Version 5:** `005_mfa_support.sql` adds three MFA tables: `user_mfa`, `mfa_recovery_codes`, and `mfa_challenges`.

The current application readiness check expects schema version 5, 19 application tables, and enabled SQLite foreign-key enforcement.

### Implemented database controls

- SQLite connection helper.
- Database directory creation.
- Foreign-key enforcement on each connection.
- Configured busy timeout.
- Transaction commit and rollback handling.
- RBAC role and permission seeding.
- SQL migrations through version 5.

The initial roles are `administrator`, `security_analyst`, and `auditor`.

### Important initialization limitation

The connection helper opens the database and enables connection settings; it does not execute `schema.sql` or apply migrations.

The current repository does not include an automated first-run database initializer or migration runner. The local database file is not tracked in Git. A fresh checkout therefore requires a correctly initialized database before the authenticated application can be used.

Do not run the base schema against an already initialized database without first checking its version and backing it up.

### Data-model implementation boundary

The schema includes assessment, test-run, finding, evidence, security-event, and audit tables. The current fixed simulation endpoints do not yet implement the complete persistent assessment lifecycle or general evidence/reporting workflows.

SHA-256 supports integrity checking; it does not prove authenticity or make SQLite audit records tamper-proof.

The original design principles and proposed future data model remain useful references, but this section describes the current database implementation.
