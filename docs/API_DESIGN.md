# SENTINEL AI - API Design

Version: 0.1
Status: Partially implemented; see current implementation status
API prefix: /api/v1

## 1. Design Principles

- REST-style JSON API.
- FastAPI implementation planned.
- Server-side authentication and authorization.
- Role-based access control (RBAC).
- Validate all incoming requests.
- Use parameterized database operations.
- Consistent error responses.
- Bounded test execution.
- Localhost-only deployment initially.
- No arbitrary code or shell execution.

## 2. Authentication Endpoints

POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
POST /api/v1/auth/change-password

Requirements:
- Passwords stored as secure password hashes.
- Random session tokens.
- Store only session token hashes.
- HttpOnly session cookies.
- SameSite cookie protection.
- CSRF protection for state-changing requests.
- Login throttling.
- Session expiration and revocation.

Never store session tokens in localStorage.

## 3. User and Role Endpoints

GET   /api/v1/admin/users
POST  /api/v1/admin/users
GET   /api/v1/admin/users/{user_id}
PATCH /api/v1/admin/users/{user_id}

GET /api/v1/admin/roles

Only administrators can manage user accounts
and role assignments.

Account removal initially uses deactivation,
not automatic destructive deletion.

## 4. Target and Model Endpoints

GET /api/v1/targets
GET /api/v1/targets/{target_id}

GET /api/v1/models
GET /api/v1/models/{model_id}

Only approved local targets are available.

External model providers are disabled initially.

## 5. Test Case Endpoints

GET /api/v1/test-cases
GET /api/v1/test-cases/{test_case_id}

Test scenarios:
AI-001 through AI-012.

Only approved and enabled test cases
can be executed.

## 6. Assessment Endpoints

POST /api/v1/assessments
GET  /api/v1/assessments
GET  /api/v1/assessments/{assessment_id}

POST /api/v1/assessments/{assessment_id}/runs

Assessment execution requirements:
- Authorized analyst.
- Approved target.
- Approved model configuration.
- Existing test case identifiers.
- Maximum 12 test cases per initial batch.
- Execution timeout.
- Initial concurrency limit of one.
- Record execution status and errors.

No arbitrary command or script execution.

## 7. Test Run Endpoints

GET /api/v1/test-runs
GET /api/v1/test-runs/{run_id}

Return execution status, timestamps,
results and associated findings.

## 8. Findings Endpoints

GET /api/v1/findings
GET /api/v1/findings/{finding_id}

Findings must contain:
- Title and description.
- Severity.
- Confidence.
- Risk score.
- Supporting test run.
- Evidence references.
- Recommended mitigation.

## 9. Evidence Endpoints

GET /api/v1/evidence
GET /api/v1/evidence/{evidence_id}

Initial release exposes evidence metadata only.

Raw evidence download remains disabled until
secure file access and path validation are implemented.

Evidence must have a verified SHA-256 hash.

## 10. Monitoring Endpoints

GET /api/v1/security-events
GET /api/v1/audit-log

Access to monitoring and audit records
depends on assigned permissions.

Authentication, administrative actions,
assessment execution and sensitive evidence access
must be recorded.

## 11. Role Permissions

Administrator:
- Manage users and roles.
- Configure targets and model profiles.
- Create and execute assessments.
- Review findings and evidence.
- Read audit records.

Security Analyst:
- View approved targets and test cases.
- Create and execute assessments.
- Review findings and evidence.
- Review security events.

Auditor:
- Read assessments and findings.
- Read evidence metadata.
- Review audit records.
- Cannot execute tests or change configuration.

All authorization is enforced server-side.

## 12. Input Validation

- Reject unknown or invalid fields.
- Validate identifiers and enum values.
- Apply request-size limits.
- Limit pagination to 100 records per request.
- Limit assessment batches to 12 test cases.
- Apply execution timeouts.
- Never accept filesystem paths from users.
- Never accept arbitrary shell commands.

## 13. HTTP Response Codes

200: Successful request.
201: Resource created.
204: Successful request with no response body.
400: Invalid request.
401: Authentication required.
403: Permission denied.
404: Resource not found.
409: State conflict.
422: Request validation failed.
429: Rate limit exceeded.
500: Unexpected server error.

Error responses must not disclose secrets,
password hashes, or internal stack traces.

## 14. API Security Requirements

- Localhost-only initial binding.
- Same-origin frontend by default.
- Restrictive CORS configuration if later required.
- CSRF protection for cookie-authenticated mutations.
- Secure session handling.
- Login rate limits.
- Request validation.
- Execution time and resource limits.
- Authorization for every protected resource.
- Audit logging for sensitive operations.

## 15. Initial Implementation Order

1. FastAPI application entry point.
2. Health endpoint.
3. Authentication service.
4. Server-side sessions.
5. RBAC middleware/dependencies.
6. User and role endpoints.
7. Target and model endpoints.
8. Test case endpoints.
9. Assessment endpoints.
10. Findings and evidence metadata endpoints.
11. Security events and audit endpoints.

## 16. Current Implementation Status

**Status reviewed: November 8, 2026**

The following routes are implemented in the current application. This inventory describes available routes, not every capability in the broader target API design.

### System routes

- `GET /health`
- `GET /health/ready`
- `GET /` (redirects to `/app/`)

### Authentication routes

Prefix: `/api/v1/auth`

- `POST /login`
- `POST /mfa/verify`
- `POST /mfa/enroll`
- `POST /mfa/enroll/confirm`
- `GET /me`
- `POST /logout`

### Target routes

Prefix: `/api/v1`

- `GET /targets`
- `POST /targets/initialize`

### Assessment creation and history routes

Prefix: `/api/v1`

- `POST /assessments` - creates a draft assessment for one or more unique registered scenario codes (AI-001 through AI-004). Requires `assessments.create`. Creates queued test-run records and an audit event; does not execute simulations.
- `GET /assessments` - returns bounded, paginated, allowlisted assessment and test-run metadata. Requires `assessments.read`; defaults to 20 records and permits a maximum limit of 100. Does not return stored execution-result payloads.
- `GET /assessments/{assessment_id}/report` - returns a sanitized report for a completed assessment and completed test run. Requires `assessments.read`. Raw execution JSON and untrusted simulation content are not returned.

Draft creation, history access, and simulation execution use separate permission checks. A queued test run is not evidence that a simulation has executed.

### Simulation routes

Prefix: `/api/v1`

- `POST /simulations/AI-001/run`
- `POST /simulations/AI-002/run`
- `POST /simulations/AI-003/run`
- `POST /simulations/AI-004/run`

### Implemented security controls

The application includes authentication and server-side authorization controls, role and permission checks, session security, MFA workflows, login throttling, and protections for authenticated state-changing requests. Simulation execution is limited to the implemented fixed scenarios and their controlled mock behavior. Assessment reports use scenario-specific allowlists and are served with `Cache-Control: no-store`.

### Not yet implemented from this specification

The following remain design requirements or planned capabilities, not available general-purpose API features:

- General model-profile CRUD and external model-provider integration.
- Arbitrary external AI target integration.
- General test-case catalog management.
- General assessment orchestration, arbitrary assessment execution, and assessment detail/update/delete operations.
- General findings and evidence APIs.
- Security-event and audit-log browsing APIs.
- General risk scoring and framework mapping.
- PDF export and downloadable reports.
- Arbitrary assessment batches and unrestricted target execution.

The database includes structures intended for some future workflows, but their existence does not imply that corresponding APIs or complete user workflows are available. Use this route inventory when operating the current release; the earlier sections remain the broader target API design.
