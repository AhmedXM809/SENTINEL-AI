"use strict";

(() => {
    const byId = (id) => document.getElementById(id);

    let csrfToken = null;
    let currentUser = null;
    let usingRecoveryCode = false;

    class ApiError extends Error {
        constructor(message, status, retryAfter) {
            super(message);
            this.name = "ApiError";
            this.status = status;
            this.retryAfter = retryAfter;
        }
    }

    async function apiRequest(path, options = {}) {
        const headers = new Headers({ Accept: "application/json" });

        if (options.body !== undefined) {
            headers.set("Content-Type", "application/json");
        }

        if (options.csrf) {
            headers.set("X-CSRF-Token", csrfToken || "");
        }

        const response = await fetch(path, {
            method: options.method || "GET",
            credentials: "same-origin",
            cache: "no-store",
            headers,
            body: options.body === undefined
                ? undefined
                : JSON.stringify(options.body)
        });

        let data = {};
        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (!response.ok) {
            throw new ApiError(
                typeof data.detail === "string"
                    ? data.detail
                    : "The request could not be completed.",
                response.status,
                response.headers.get("Retry-After")
            );
        }

        return { response, data };
    }

    function showFeedback(element, message, type = "error") {
        element.textContent = message;
        element.className = `feedback ${type}`;
        element.hidden = false;
    }

    function clearFeedback(element) {
        element.textContent = "";
        element.hidden = true;
    }

    function scrollToSimulationResults(elementId) {
        const results = byId(elementId);
        if (!results || results.hidden) return;

        window.requestAnimationFrame(() => {
            const reduceMotion = window.matchMedia(
                "(prefers-reduced-motion: reduce)"
            ).matches;

            results.scrollIntoView({
                behavior: reduceMotion ? "auto" : "smooth",
                block: "start"
            });
        });
    }

    function showLogin() {
        csrfToken = null;
        currentUser = null;
        byId("workspace").hidden = true;
        byId("auth-screen").hidden = false;
        byId("login-view").hidden = false;
        byId("mfa-view").hidden = true;
        byId("auth-loading").hidden = true;
        byId("username").focus();
    }

    function showMfa() {
        byId("login-view").hidden = true;
        byId("mfa-view").hidden = false;
        byId("mfa-code").value = "";
        clearFeedback(byId("mfa-feedback"));
        byId("mfa-code-label").textContent = "Authenticator code";
        byId("mfa-code").placeholder = "000000";
        byId("mfa-code").inputMode = "numeric";
        usingRecoveryCode = false;
        byId("recovery-toggle").textContent = "Use a recovery code instead";
        byId("mfa-code").focus();
    }

    async function loadDashboard() {
        const { data } = await apiRequest("/api/v1/auth/me");

        if (data.authenticated !== true || !data.user) {
            throw new ApiError("Your session is no longer valid.", 401);
        }

        csrfToken = data.csrf_token;
        currentUser = data.user;

        const name = String(currentUser.username || "Analyst");
        const roles = Array.isArray(currentUser.roles) ? currentUser.roles : [];
        const primaryRole = roles.length
            ? roles.map((item) => String(item).replaceAll("_", " ")).join(" · ")
            : "AUTHENTICATED USER";

        byId("display-username").textContent = name;
        byId("display-role").textContent = primaryRole.toUpperCase();
        byId("user-avatar").textContent = name.slice(0, 1).toUpperCase();

        byId("auth-screen").hidden = true;
        byId("workspace").hidden = false;

        await refreshPlatformStatus();
        applyCurrentView();
    }

    async function refreshPlatformStatus() {
        const apiStatus = byId("api-status");
        const apiDetail = byId("api-detail");
        const dbStatus = byId("database-status");
        const dbDetail = byId("database-detail");

        try {
            const { data } = await apiRequest("/health/ready");

            apiStatus.textContent = "Operational";
            apiStatus.className = "status-value positive";
            apiDetail.textContent = "FastAPI service is responding.";

            dbStatus.textContent = "Connected";
            dbStatus.className = "status-value positive";
            dbDetail.textContent =
                `SQLite schema v${data.schema_version} · ${data.tables} tables · foreign keys ${data.foreign_keys}.`;
        } catch {
            apiStatus.textContent = "Unavailable";
            apiStatus.className = "status-value";
            apiDetail.textContent = "The readiness endpoint could not be reached.";

            dbStatus.textContent = "Unknown";
            dbStatus.className = "status-value";
            dbDetail.textContent = "Database readiness could not be confirmed.";
        }
    }

    function showLoginError(error) {
        if (error.status === 429) {
            const delay = error.retryAfter
                ? ` Try again after ${error.retryAfter} seconds.`
                : " Please wait before trying again.";
            return `Sign-in is temporarily delayed.${delay}`;
        }
        if (error.status === 401) {
            return "The username or password was not accepted.";
        }
        if (error.status === 403) {
            return "This browser origin is not authorized by the local API.";
        }
        if (error.status === 503) {
            return "The authentication service is temporarily unavailable.";
        }
        return "Sign-in could not be completed. Check that the local API is running.";
    }

    byId("login-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = byId("login-button");
        const feedback = byId("login-feedback");
        const username = byId("username").value.trim();
        const passwordInput = byId("password");
        const password = passwordInput.value;

        clearFeedback(feedback);

        if (!username || !password) {
            showFeedback(feedback, "Enter your username and password.");
            return;
        }

        button.disabled = true;
        button.querySelector("span:first-child").textContent = "Authenticating…";

        try {
            const { response, data } = await apiRequest("/api/v1/auth/login", {
                method: "POST",
                body: { username, password }
            });

            passwordInput.value = "";

            if (response.status === 202 && data.mfa_required === true) {
                showMfa();
                return;
            }

            if (data.authenticated === true) {
                await loadDashboard();
                return;
            }

            throw new ApiError("Unexpected authentication response.", response.status);
        } catch (error) {
            passwordInput.value = "";
            showFeedback(feedback, showLoginError(error));
        } finally {
            button.disabled = false;
            button.querySelector("span:first-child").textContent = "Continue securely";
        }
    });

    byId("recovery-toggle").addEventListener("click", () => {
        usingRecoveryCode = !usingRecoveryCode;
        const input = byId("mfa-code");
        input.value = "";

        if (usingRecoveryCode) {
            byId("mfa-code-label").textContent = "Recovery code";
            input.placeholder = "Enter one unused recovery code";
            input.inputMode = "text";
            input.autocomplete = "off";
            byId("recovery-toggle").textContent = "Use an authenticator code instead";
        } else {
            byId("mfa-code-label").textContent = "Authenticator code";
            input.placeholder = "000000";
            input.inputMode = "numeric";
            input.autocomplete = "one-time-code";
            byId("recovery-toggle").textContent = "Use a recovery code instead";
        }

        clearFeedback(byId("mfa-feedback"));
        input.focus();
    });

    byId("mfa-form").addEventListener("submit", async (event) => {
        event.preventDefault();

        const button = byId("mfa-button");
        const input = byId("mfa-code");
        const feedback = byId("mfa-feedback");
        const code = input.value.trim();

        clearFeedback(feedback);

        if (!usingRecoveryCode && !/^\d{6}$/.test(code)) {
            showFeedback(feedback, "Enter the current six-digit authenticator code.");
            return;
        }

        if (usingRecoveryCode && (code.length < 6 || code.length > 64)) {
            showFeedback(feedback, "Enter a valid unused recovery code.");
            return;
        }

        button.disabled = true;
        button.querySelector("span:first-child").textContent = "Verifying…";
        input.value = "";

        try {
            const { data } = await apiRequest("/api/v1/auth/mfa/verify", {
                method: "POST",
                body: { code }
            });

            if (data.authenticated !== true) {
                throw new ApiError("MFA authentication was not confirmed.", 401);
            }

            await loadDashboard();
        } catch (error) {
            if (error.status === 429) {
                const delay = error.retryAfter
                    ? ` Wait ${error.retryAfter} seconds before trying again.`
                    : " Wait before trying again.";
                showFeedback(feedback, `Verification is temporarily delayed.${delay}`);
            } else if (error.status === 401) {
                showFeedback(
                    feedback,
                    "Verification was not accepted. Check the code and challenge, then try again."
                );
            } else {
                showFeedback(feedback, "MFA verification could not be completed.");
            }
        } finally {
            button.disabled = false;
            button.querySelector("span:first-child").textContent = "Verify and sign in";
        }
    });

    byId("back-to-login").addEventListener("click", () => {
        byId("mfa-view").hidden = true;
        byId("login-view").hidden = false;
        byId("mfa-code").value = "";
        clearFeedback(byId("mfa-feedback"));
        byId("password").value = "";
        byId("username").focus();
    });

    byId("logout-button").addEventListener("click", async () => {
        const button = byId("logout-button");
        button.disabled = true;

        try {
            await apiRequest("/api/v1/auth/logout", {
                method: "POST",
                csrf: true,
                body: {}
            });
            showLogin();
        } catch (error) {
            if (error.status === 401) {
                showLogin();
            } else {
                const message = error.status === 403
                    ? "Sign-out was rejected by CSRF protection. Refresh the page and try again."
                    : "Sign-out could not be completed. Your server-side session may still be active.";
                const feedback = byId("global-feedback");
                feedback.textContent = message;
                feedback.hidden = false;
            }
        } finally {
            button.disabled = false;
        }
    });

    function setTargetsFeedback(message, type = "info") {
        const element = byId("targets-feedback");
        element.textContent = message;
        element.className = `feedback ${type}`;
        element.hidden = false;
    }

    function clearTargetsFeedback() {
        const element = byId("targets-feedback");
        element.textContent = "";
        element.hidden = true;
    }

    function createTextElement(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = String(text ?? "");
        return element;
    }

    function renderTargetCard(target) {
        const card = document.createElement("article");
        card.className = "target-card";

        const header = document.createElement("div");
        header.className = "target-card-header";

        const type = createTextElement(
            "span",
            `target-type-chip ${target.target_type === "secure" ? "secure" : "vulnerable"}`,
            target.target_type === "secure" ? "SECURE TARGET" : "VULNERABLE TARGET"
        );

        const state = createTextElement(
            "span",
            `target-state-chip ${target.is_enabled ? "enabled" : "disabled"}`,
            target.is_enabled ? "ENABLED" : "DISABLED"
        );

        header.append(type, state);
        card.append(header);

        card.append(createTextElement("h3", "", target.name));

        const description = target.target_type === "secure"
            ? "Protected training target profile intended for defensive validation."
            : "Deliberately vulnerable training profile for controlled synthetic security testing.";

        card.append(createTextElement("p", "", description));

        const metadata = document.createElement("div");
        metadata.className = "target-metadata";

        metadata.append(
            createTextElement(
                "span",
                "metadata-pill",
                target.security_mode.replaceAll("_", " ")
            ),
            createTextElement(
                "span",
                "metadata-pill",
                `ID · ${target.id}`
            )
        );

        card.append(metadata);
        return card;
    }

    function renderModelCard(model) {
        const card = document.createElement("article");
        card.className = "model-card";

        const header = document.createElement("div");
        header.className = "model-card-header";

        header.append(
            createTextElement("span", "target-type-chip secure", "LOCAL MOCK"),
            createTextElement("span", "target-state-chip disabled", "NO EXTERNAL PROVIDER")
        );

        card.append(header);
        card.append(createTextElement("h3", "", model.name));

        card.append(
            createTextElement(
                "p",
                "",
                "Deterministic local response adapter. It does not connect to an external AI provider."
            )
        );

        const metadata = document.createElement("div");
        metadata.className = "model-metadata";

        metadata.append(
            createTextElement("span", "metadata-pill", model.provider_type),
            createTextElement("span", "metadata-pill", model.model_identifier)
        );

        card.append(metadata);
        return card;
    }

    async function loadTargets() {
        const targetList = byId("targets-list");
        const modelList = byId("models-list");
        const targetEmpty = byId("targets-empty");
        const modelEmpty = byId("models-empty");
        const initializeButton = byId("initialize-targets-button");

        targetList.replaceChildren();
        modelList.replaceChildren();
        clearTargetsFeedback();

        try {
            const { data } = await apiRequest("/api/v1/targets");

            const targets = Array.isArray(data.targets) ? data.targets : [];
            const models = Array.isArray(data.models) ? data.models : [];

            byId("target-count").textContent = String(targets.length);
            byId("model-count").textContent = String(models.length);

            targetEmpty.hidden = targets.length !== 0;
            modelEmpty.hidden = models.length !== 0;

            for (const target of targets) {
                targetList.append(renderTargetCard(target));
            }

            for (const model of models) {
                modelList.append(renderModelCard(model));
            }

            const canManage = Array.isArray(currentUser?.permissions)
                && currentUser.permissions.includes("targets.manage");

            initializeButton.hidden = !canManage || targets.length >= 2;

            if (targets.length === 0 && !canManage) {
                setTargetsFeedback(
                    "No target profiles are initialized. Contact an administrator to provision the approved profiles."
                );
            }

            return true;
        } catch (error) {
            byId("target-count").textContent = "—";
            byId("model-count").textContent = "—";
            initializeButton.hidden = true;

            if (error.status === 401) {
                showLogin();
                return false;
            }

            const message = error.status === 403
                ? "Your role does not have permission to view AI targets."
                : "Target inventory could not be loaded. Check the local API and try again.";

            setTargetsFeedback(message, "error");
            return false;
        }
    }


    function applyCurrentView() {
        if (!currentUser) return;

        const permissions = Array.isArray(currentUser.permissions)
            ? currentUser.permissions
            : [];

        const canReadTargets = permissions.includes("targets.read");
        const canExecuteAssessments = permissions.includes("assessments.execute")
            && permissions.includes("targets.read");
        let selectedView = window.location.hash.replace(/^#/, "");

        if (!["targets", "assessments", "overview"].includes(selectedView)) {
            selectedView = "overview";
        }

        let deniedMessage = "";
        if (selectedView === "targets" && !canReadTargets) {
            deniedMessage = "Your role does not have permission to view AI targets.";
            selectedView = "overview";
        }
        if (selectedView === "assessments" && !canExecuteAssessments) {
            deniedMessage = "Your role does not have permission to execute AI security assessments.";
            selectedView = "overview";
        }

        if (deniedMessage) {
            history.replaceState(null, "", window.location.pathname + window.location.search);
            showFeedback(byId("global-feedback"), deniedMessage, "error");
            byId("global-feedback").hidden = false;
        }

        const overviewSelected = selectedView === "overview";
        const targetsSelected = selectedView === "targets";
        const assessmentsSelected = selectedView === "assessments";

        byId("overview-page").hidden = !overviewSelected;
        byId("targets-page").hidden = !targetsSelected;
        byId("assessments-page").hidden = !assessmentsSelected;

        byId("overview-nav").classList.toggle("active", overviewSelected);
        byId("targets-nav").hidden = !canReadTargets;
        byId("targets-nav").classList.toggle("active", targetsSelected);
        byId("assessments-nav").hidden = !canExecuteAssessments;
        byId("assessments-nav").classList.toggle("active", assessmentsSelected);
        byId("assessments-module-card").hidden = !canExecuteAssessments;

        byId("overview-nav").setAttribute("aria-current", overviewSelected ? "page" : "false");
        byId("targets-nav").setAttribute("aria-current", targetsSelected ? "page" : "false");
        byId("assessments-nav").setAttribute("aria-current", assessmentsSelected ? "page" : "false");

        if (targetsSelected) void loadTargets();
        if (targetsSelected || assessmentsSelected) {
            window.scrollTo({ top: 0, behavior: "smooth" });
        }
    }
    byId("refresh-targets-button").addEventListener("click", () => {
        void loadTargets();
    });

    byId("initialize-targets-button").addEventListener("click", async () => {
        const button = byId("initialize-targets-button");

        if (!window.confirm(
            "Initialize TestGPT-Vulnerable, TestGPT-Secure, and the deterministic mock model? Both targets will remain disabled. No assessment will run."
        )) {
            return;
        }

        button.disabled = true;
        button.querySelector("span:first-child").textContent = "Initializing…";

        try {
            const { data } = await apiRequest("/api/v1/targets/initialize", {
                method: "POST",
                csrf: true,
                body: {}
            });

            const refreshed = await loadTargets();
            if (!refreshed) {
                return;
            }

            setTargetsFeedback(
                `Initialization complete: ${data.created_targets} target profiles and ${data.created_models} model profiles created. Both targets remain disabled. No tests were executed.`,
                "info"
            );
        } catch (error) {
            if (error.status === 401) {
                showLogin();
                return;
            }

            const message = error.status === 403
                ? "Your account does not have target-management permission, or CSRF validation failed."
                : error.status === 409
                    ? "A standard target or model identifier conflicts with an existing profile. No conflicting record was overwritten."
                    : "Target initialization failed. The database transaction was not confirmed.";

            setTargetsFeedback(message, "error");
        } finally {
            button.disabled = false;
            button.querySelector("span:first-child").textContent = "Initialize standard targets";
        }
    });

    function hasPersistedHistory(data) {
        return (
            data?.audit_recorded === true
            && data?.history_persisted === true
            && data?.assessment_created === true
            && data?.test_run_created === true
            && typeof data?.assessment_id === "string"
            && data.assessment_id.length > 0
            && typeof data?.test_run_id === "string"
            && data.test_run_id.length > 0
            && data?.finding_created === false
            && data?.evidence_persisted === false
        );
    }

    function renderAI001Results(data) {
        const result = data?.simulation;
        if (
            !result
            || result.scenario_id !== "AI-001"
            || !result.vulnerable_target
            || !result.secure_target
            || !result.evaluation
        ) {
            throw new Error("The AI-001 result structure was not valid.");
        }

        const vulnerable = result.vulnerable_target;
        const secure = result.secure_target;
        const evaluation = result.evaluation;
        const persistenceValid = hasPersistedHistory(data);

        const passed = (
            persistenceValid
            && evaluation.blue_team_control === "PASS"
            && evaluation.secure_target_blocked === true
            && evaluation.vulnerable_target_disclosed_canary === true
            && evaluation.secure_target_disclosed_canary === false
        );

        const overall = byId("ai001-overall-status");
        overall.textContent = passed ? "BLUE TEAM CONTROL: PASS" : "REVIEW REQUIRED";
        overall.className = passed ? "assessment-outcome pass" : "assessment-outcome review";

        byId("ai001-execution-type").textContent = String(result.execution_type || "Not reported");
        byId("ai001-input-classification").textContent = String(result.input_classification || "Not reported");
        byId("ai001-audit-status").textContent = persistenceValid
            ? "Audit and assessment history saved"
            : "History save not confirmed";

        const vulnerableState = byId("ai001-vulnerable-state");
        vulnerableState.textContent = vulnerable.blocked ? "BLOCKED" : "NOT BLOCKED";
        vulnerableState.className = vulnerable.blocked ? "result-state blocked" : "result-state unblocked";

        const secureState = byId("ai001-secure-state");
        secureState.textContent = secure.blocked ? "BLOCKED" : "NOT BLOCKED";
        secureState.className = secure.blocked ? "result-state blocked" : "result-state unblocked";

        byId("ai001-vulnerable-output").textContent = String(vulnerable.output || "No simulated output returned.");
        byId("ai001-secure-output").textContent = String(secure.output || "No simulated output returned.");
        byId("ai001-vulnerable-disclosure").textContent = vulnerable.synthetic_disclosure_detected === true
            ? "Synthetic canary disclosed"
            : "No synthetic disclosure detected";
        byId("ai001-secure-disclosure").textContent = secure.synthetic_disclosure_detected === true
            ? "Synthetic canary disclosed"
            : "No synthetic disclosure detected";

        const vulnerableRules = Array.isArray(vulnerable.detection_rule_ids) ? vulnerable.detection_rule_ids : [];
        const secureRules = Array.isArray(secure.detection_rule_ids) ? secure.detection_rule_ids : [];
        byId("ai001-vulnerable-rules").textContent = vulnerableRules.length
            ? vulnerableRules.join(" / ")
            : "No rules triggered.";
        byId("ai001-secure-rules").textContent = secureRules.length
            ? secureRules.join(" / ")
            : "No rules triggered.";

        byId("ai001-injection-status").textContent = evaluation.injection_signature_detected === true
            ? "Detected"
            : "Not detected";
        byId("ai001-block-status").textContent = evaluation.secure_target_blocked === true
            ? "Blocked"
            : "Not blocked";
        byId("ai001-controls-status").textContent = String(evaluation.blue_team_control || "Not reported");
        byId("ai001-disclosure-status").textContent = evaluation.secure_target_disclosed_canary === false
            ? "No disclosure"
            : "Disclosure detected";
        byId("ai001-limitations").textContent = String(result.limitations || "No limitations were reported.");
        byId("assessment-results").hidden = false;
    }

    async function runAI001() {
        const permissions = Array.isArray(currentUser?.permissions) ? currentUser.permissions : [];
        if (
            !permissions.includes("assessments.execute")
            || !permissions.includes("targets.read")
        ) {
            showFeedback(byId("assessment-feedback"), "Your account does not have assessment-execution permission.", "error");
            return;
        }

        const confirmed = window.confirm(
            "Run the fixed AI-001 deterministic training simulation?\n\n"
            + "It uses synthetic data and a local mock engine only.\n"
            + "A sanitized simulation result, assessment, test run, and audit entry are saved locally. No findings or evidence records are created. Targets remain disabled and no external AI provider is contacted.\n\n"
            + "Continue?"
        );
        if (!confirmed) return;

        const button = byId("run-ai001-button");
        const label = button.querySelector("span:first-child");
        button.disabled = true;
        label.textContent = "Running controlled simulation...";
        clearFeedback(byId("assessment-feedback"));
        byId("assessment-results").hidden = true;

        try {
            const { data } = await apiRequest("/api/v1/simulations/AI-001/run", {
                method: "POST",
                csrf: true,
                body: {}
            });
            renderAI001Results(data);
            showFeedback(
                byId("assessment-feedback"),
                "AI-001 completed. The sanitized result, assessment history, and audit event were saved locally; no findings or evidence records were created.",
                "info"
            );
            scrollToSimulationResults("assessment-results");
        } catch (error) {
            if (error.status === 401) {
                showLogin();
                return;
            }
            const message = error.status === 403
                ? "Execution was rejected. Check your assessment permission and authenticated session."
                : error.status === 409
                    ? "Execution was blocked because the target profiles or deterministic mock configuration do not meet the required safety checks."
                    : error.status === 503
                        ? "The local database was unavailable. No successful execution was confirmed."
                        : "AI-001 could not be completed. No successful result was confirmed.";
            showFeedback(byId("assessment-feedback"), message, "error");
        } finally {
            button.disabled = false;
            label.textContent = "Run AI-001 simulation";
        }
    }

    byId("run-ai001-button").addEventListener("click", () => {
        void runAI001();
    });
    function renderAI002Results(data) {
        const result = data?.simulation;
        if (
            !result
            || result.scenario_id !== "AI-002"
            || !result.document_inspection
            || !result.vulnerable_target
            || !result.secure_target
            || !result.evaluation
        ) {
            throw new Error("The AI-002 result structure was not valid.");
        }

        const inspection = result.document_inspection;
        const vulnerable = result.vulnerable_target;
        const secure = result.secure_target;
        const evaluation = result.evaluation;

        const inspectionRules = Array.isArray(inspection.rule_ids)
            ? inspection.rule_ids
            : [];
        const vulnerableRules = Array.isArray(vulnerable.detection_rule_ids)
            ? vulnerable.detection_rule_ids
            : [];
        const secureRules = Array.isArray(secure.detection_rule_ids)
            ? secure.detection_rule_ids
            : [];

        const persistenceValid = hasPersistedHistory(data);

        const passed = (
            persistenceValid
            && evaluation.blue_team_control === "PASS"
            && evaluation.indirect_injection_detected === true
            && evaluation.vulnerable_target_disclosed_canary === true
            && evaluation.secure_target_blocked === true
            && evaluation.secure_target_treated_document_as_untrusted === true
            && evaluation.secure_target_disclosed_canary === false
            && result.retrieved_document_content_returned === false
        );

        const overall = byId("ai002-overall-status");
        overall.textContent = passed ? "BLUE TEAM CONTROL: PASS" : "REVIEW REQUIRED";
        overall.className = passed ? "assessment-outcome pass" : "assessment-outcome review";

        byId("ai002-execution-type").textContent = String(result.execution_type || "Not reported");
        byId("ai002-document-id").textContent = String(result.retrieved_document_id || "Not reported");
        byId("ai002-audit-status").textContent = persistenceValid
            ? "Audit and assessment history saved"
            : "History save not confirmed";

        byId("ai002-override-status").textContent = inspectionRules.includes("RAG-INDIRECT-OVERRIDE") ? "Detected" : "Not detected";
        byId("ai002-role-status").textContent = inspectionRules.includes("RAG-ROLE-ESCALATION") ? "Detected" : "Not detected";
        byId("ai002-exfiltration-status").textContent = inspectionRules.includes("RAG-SYNTHETIC-DATA-EXFILTRATION") ? "Detected" : "Not detected";
        byId("ai002-document-content-status").textContent = result.retrieved_document_content_returned === false
            ? "Withheld from response"
            : "Unexpectedly returned";
        byId("ai002-inspection-rules").textContent = inspectionRules.length
            ? inspectionRules.join(" / ")
            : "No inspection rules triggered.";

        const vulnerableState = byId("ai002-vulnerable-state");
        vulnerableState.textContent = vulnerable.blocked ? "BLOCKED" : "NOT BLOCKED";
        vulnerableState.className = vulnerable.blocked ? "result-state blocked" : "result-state unblocked";

        const secureState = byId("ai002-secure-state");
        secureState.textContent = secure.blocked ? "BLOCKED" : "NOT BLOCKED";
        secureState.className = secure.blocked ? "result-state blocked" : "result-state unblocked";

        byId("ai002-vulnerable-output").textContent = String(vulnerable.output || "No simulated output returned.");
        byId("ai002-secure-output").textContent = String(secure.output || "No simulated output returned.");
        byId("ai002-vulnerable-disclosure").textContent = vulnerable.synthetic_disclosure_detected === true
            ? "Synthetic canary disclosed"
            : "No synthetic disclosure detected";
        byId("ai002-secure-disclosure").textContent = secure.synthetic_disclosure_detected === true
            ? "Synthetic canary disclosed"
            : "No synthetic disclosure detected";

        byId("ai002-vulnerable-rules").textContent = vulnerableRules.length
            ? vulnerableRules.join(" / ")
            : "No target-applied rules.";
        byId("ai002-secure-rules").textContent = secureRules.length
            ? secureRules.join(" / ")
            : "No rules triggered.";

        byId("ai002-injection-status").textContent = evaluation.indirect_injection_detected === true ? "Detected" : "Not detected";
        byId("ai002-block-status").textContent = evaluation.secure_target_blocked === true ? "Blocked" : "Not blocked";
        byId("ai002-untrusted-status").textContent = evaluation.secure_target_treated_document_as_untrusted === true ? "Enforced" : "Not confirmed";
        byId("ai002-controls-status").textContent = String(evaluation.blue_team_control || "Not reported");
        byId("ai002-limitations").textContent = String(result.limitations || "No limitations were reported.");

        byId("ai002-results").hidden = false;
    }

    async function runAI002() {
        const permissions = Array.isArray(currentUser?.permissions)
            ? currentUser.permissions
            : [];

        if (
            !permissions.includes("assessments.execute")
            || !permissions.includes("targets.read")
        ) {
            showFeedback(
                byId("assessment-feedback"),
                "Your account does not have the permissions required to execute this assessment.",
                "error"
            );
            return;
        }

        const confirmed = window.confirm(
            "Run the fixed AI-002 indirect prompt-injection simulation?\n\n"
            + "It uses one synthetic retrieved document and a deterministic local mock only.\n"
            + "The raw retrieved document is not returned or stored. A sanitized assessment history and audit entry are saved locally; "
            + "no finding or evidence records are created. "
            + "Targets remain disabled and no external AI provider is contacted.\n\n"
            + "Continue?"
        );
        if (!confirmed) return;

        const button = byId("run-ai002-button");
        const label = button.querySelector("span:first-child");
        button.disabled = true;
        label.textContent = "Running controlled simulation...";
        clearFeedback(byId("assessment-feedback"));
        byId("ai002-results").hidden = true;

        try {
            const { data } = await apiRequest("/api/v1/simulations/AI-002/run", {
                method: "POST",
                csrf: true,
                body: {}
            });
            renderAI002Results(data);
            showFeedback(
                byId("assessment-feedback"),
                "AI-002 completed. The sanitized result, assessment history, and audit event were saved locally; no findings or evidence records were created.",
                "info"
            );
            scrollToSimulationResults("ai002-results");
        } catch (error) {
            if (error.status === 401) {
                showLogin();
                return;
            }
            const message = error.status === 403
                ? "Execution was rejected. Check your assessment permissions and authenticated session."
                : error.status === 409
                    ? "Execution was blocked because the target profiles or deterministic mock configuration do not meet the required safety checks."
                    : error.status === 503
                        ? "The local database was unavailable. No successful execution was confirmed."
                        : "AI-002 could not be completed. No successful result was confirmed.";
            showFeedback(byId("assessment-feedback"), message, "error");
        } finally {
            button.disabled = false;
            label.textContent = "Run AI-002 simulation";
        }
    }

    byId("run-ai002-button").addEventListener("click", () => {
        void runAI002();
    });

    function renderAI003Results(data) {
        const result = data?.simulation;

        if (
            !result
            || result.scenario_id !== "AI-003"
            || !result.vulnerable_agent
            || !result.secure_agent
            || !Array.isArray(result.vulnerable_agent.results)
            || !Array.isArray(result.secure_agent.results)
        ) {
            throw new Error("The AI-003 result structure was not valid.");
        }

        const vulnerable = result.vulnerable_agent;
        const secure = result.secure_agent;
        const vulnerableResults = vulnerable.results;
        const secureResults = secure.results;

        const formatToolDecisions = (items) => items.map((item, index) => {
            const rules = Array.isArray(item.detection_rules)
                ? item.detection_rules.filter((rule) => typeof rule === "string")
                : [];
            const controls = Array.isArray(item.policy_controls)
                ? item.policy_controls.filter((control) => typeof control === "string")
                : [];

            const mappingStatus = item.policy_permission_mapping_match === true
                ? "MATCH"
                : item.policy_permission_mapping_match === false
                    ? "MISMATCH"
                    : "NOT REPORTED";

            const permissionStatus = item.required_permission_granted === true
                ? "GRANTED"
                : item.required_permission_granted === false
                    ? "NOT GRANTED"
                    : "NOT REPORTED";

            const approvalStatus = item.approval_required === true
                ? "REQUIRED"
                : item.approval_required === false
                    ? "NOT REQUIRED BY THIS DECISION"
                    : "NOT REPORTED";

            const executionStatus = item.execution_performed === false
                ? "NO"
                : item.execution_performed === true
                    ? "YES - UNEXPECTED"
                    : "NOT REPORTED";

            return [
                `${index + 1}. ${String(item.tool_name || "Unknown tool")}`,
                `   Agent decision: ${String(item.decision || "Not reported")}`,
                `   Accepted: ${item.accepted === true ? "YES" : "NO"}`,
                `   Policy outcome: ${String(item.policy_outcome || "NOT REPORTED")}`,
                `   Policy reason: ${String(item.policy_reason_code || "NOT REPORTED")}`,
                `   Risk level: ${String(item.policy_risk_level || "NOT REPORTED")}`,
                `   Permission mapping: ${mappingStatus}`,
                `   Required permission: ${permissionStatus}`,
                `   Human approval: ${approvalStatus}`,
                `   Execution performed: ${executionStatus}`,
                `   Policy controls: ${controls.length ? controls.join(" / ") : "None reported"}`,
                `   Detection rules: ${rules.length ? rules.join(" / ") : "None"}`
            ].join("\n");
        }).join("\n\n");

        const secureRuleIds = [
            ...new Set(
                secureResults.flatMap((item) => (
                    Array.isArray(item.detection_rules)
                        ? item.detection_rules
                        : []
                ))
            )
        ];

        const vulnerableAccepted = vulnerableResults.filter(
            (item) => item.accepted === true
        ).length;
        const secureDenied = secureResults.filter(
            (item) => item.accepted === false
        ).length;

        const allowlistEnforced = secureRuleIds.includes("AGENT-ALLOWLIST-001");
        const permissionEnforced = secureRuleIds.includes("AGENT-PERM-001");

        const validPolicyOutcomes = new Set([
            "ALLOW",
            "DENY",
            "REQUIRE_APPROVAL"
        ]);

        const policyContractValid = (
            secureResults.length === 4
            && secureResults.every((item) => (
                item
                && validPolicyOutcomes.has(item.policy_outcome)
                && typeof item.policy_reason_code === "string"
                && typeof item.policy_risk_level === "string"
                && typeof item.policy_permission_mapping_match === "boolean"
                && typeof item.required_permission_granted === "boolean"
                && typeof item.approval_required === "boolean"
                && item.execution_performed === false
            ))
        );

        const policyEnforced = (
            policyContractValid
            && secureResults.every((item) => (
                item.accepted === false
                && item.policy_outcome === "DENY"
                && item.execution_performed === false
            ))
        );

        const policyDeniedCount = secureResults.filter(
            (item) => item.policy_outcome === "DENY"
        ).length;

        const noRealOperations = (
            result.real_tools_invoked === false
            && result.real_shell_used === false
            && result.real_filesystem_accessed === false
            && result.real_network_requests_sent === false
            && result.real_accounts_modified === false
        );

        const persistenceValid = hasPersistedHistory(data);

        const passed = (
            persistenceValid
            && result.simulation_only === true
            && result.persisted === false
            && result.attempt_count === 4
            && vulnerableResults.length === 4
            && secureResults.length === 4
            && vulnerableAccepted === 4
            && vulnerable.canary_exposed === true
            && secureDenied === 4
            && secure.canary_exposed === false
            && allowlistEnforced
            && permissionEnforced
            && policyEnforced
            && noRealOperations
            && result.blue_team_control === "PASS"
            && result.assessment_result === "PASS"
        );

        const overall = byId("ai003-overall-status");
        overall.textContent = passed
            ? "BLUE TEAM CONTROL: PASS"
            : "REVIEW REQUIRED";
        overall.className = passed
            ? "assessment-outcome pass"
            : "assessment-outcome review";

        byId("ai003-execution-type").textContent = "Deterministic in-memory mock";
        byId("ai003-attempt-count").textContent = String(result.attempt_count ?? "Not reported");
        byId("ai003-audit-status").textContent = persistenceValid
            ? "Audit and assessment history saved"
            : "History save not confirmed";

        const vulnerableState = byId("ai003-vulnerable-state");
        vulnerableState.textContent = `${vulnerableAccepted} / 4 ACCEPTED`;
        vulnerableState.className = vulnerableAccepted === 4
            ? "result-state unblocked"
            : "result-state";

        const secureState = byId("ai003-secure-state");
        secureState.textContent = `${secureDenied} / 4 DENIED`;
        secureState.className = secureDenied === 4
            ? "result-state blocked"
            : "result-state unblocked";

        byId("ai003-vulnerable-accepted").textContent =
            `${vulnerableAccepted} of 4 unauthorized requests accepted`;
        byId("ai003-vulnerable-canary").textContent =
            vulnerable.canary_exposed === true
                ? "Exposed by vulnerable mock"
                : "No exposure reported";

        byId("ai003-secure-denied").textContent =
            `${secureDenied} of 4 requests denied`;
        byId("ai003-secure-canary").textContent =
            secure.canary_exposed === false
                ? "Not exposed by protected mock"
                : "Exposure detected or not confirmed";

        byId("ai003-vulnerable-details").textContent =
            formatToolDecisions(vulnerableResults);
        byId("ai003-secure-details").textContent =
            formatToolDecisions(secureResults);

        byId("ai003-allowlist-status").textContent =
            allowlistEnforced ? "Enforced / rule triggered" : "Not confirmed";
        byId("ai003-permission-status").textContent =
            permissionEnforced ? "Enforced / rule triggered" : "Not confirmed";
        byId("ai003-real-operations-status").textContent =
            noRealOperations ? "None invoked" : "Unexpected activity reported";
        byId("ai003-controls-status").textContent =
            String(result.blue_team_control || "Not reported");

        byId("ai003-policy-engine-status").textContent = policyEnforced
            ? "ENFORCED / 4 OF 4 DENIED"
            : "NOT CONFIRMED";

        byId("ai003-policy-engine-detail").textContent = policyEnforced
            ? `${policyDeniedCount} of ${secureResults.length} protected-agent requests received DENY decisions. All four reported execution_performed=false.`
            : "The policy result contract was incomplete or at least one protected-agent request was not safely denied.";

        byId("ai003-limitations").textContent = Array.isArray(result.limitations)
            ? result.limitations.join(" ")
            : "No limitations were reported.";

        byId("ai003-results").hidden = false;
    }

    async function runAI003() {
        const permissions = Array.isArray(currentUser?.permissions)
            ? currentUser.permissions
            : [];

        if (
            !permissions.includes("assessments.execute")
            || !permissions.includes("targets.read")
        ) {
            showFeedback(
                byId("assessment-feedback"),
                "Your account does not have the permissions required to execute this assessment.",
                "error"
            );
            return;
        }

        const confirmed = window.confirm(
            "Run the fixed AI-003 agent tool-misuse simulation?\n\n"
            + "It evaluates four synthetic tool requests against vulnerable and protected mock agents.\n"
            + "No real shell, filesystem, network, or account operations are performed. "
            + "A sanitized assessment history and audit event are saved locally; no finding or evidence "
            + "records are created. No external AI provider is contacted.\n\n"
            + "Continue?"
        );
        if (!confirmed) return;

        const button = byId("run-ai003-button");
        const label = button.querySelector("span:first-child");
        button.disabled = true;
        label.textContent = "Running controlled simulation...";
        clearFeedback(byId("assessment-feedback"));
        byId("ai003-results").hidden = true;

        try {
            const { data } = await apiRequest("/api/v1/simulations/AI-003/run", {
                method: "POST",
                csrf: true,
                body: {}
            });

            renderAI003Results(data);
            showFeedback(
                byId("assessment-feedback"),
                "AI-003 completed. The sanitized report, assessment history, and audit event were saved locally; no findings or evidence records were created.",
                "info"
            );
            scrollToSimulationResults("ai003-results");
        } catch (error) {
            if (error.status === 401) {
                showLogin();
                return;
            }

            const message = error.status === 403
                ? "Execution was rejected. Check your assessment permissions and authenticated session."
                : error.status === 409
                    ? "Execution was blocked because the training profiles or deterministic mock configuration do not meet the required safety checks."
                    : error.status === 503
                        ? "The local database was unavailable. No successful execution was confirmed."
                        : "AI-003 could not be completed. No successful result was confirmed.";

            showFeedback(byId("assessment-feedback"), message, "error");
        } finally {
            button.disabled = false;
            label.textContent = "Run AI-003 simulation";
        }
    }

    byId("run-ai003-button").addEventListener("click", () => {
        void runAI003();
    });


    function renderAI004Results(data) {
        const result = data?.simulation;
        const evaluation = result?.evaluation;
        const vulnerable = result?.vulnerable_agent;
        const secure = result?.secure_agent;

        if (
            !result
            || result.scenario_id !== "AI-004"
            || !evaluation
            || !vulnerable
            || !secure
            || !Array.isArray(vulnerable.ingestion_decisions)
            || !Array.isArray(vulnerable.retrieval_decisions)
            || !Array.isArray(secure.ingestion_decisions)
            || !Array.isArray(secure.retrieval_decisions)
        ) {
            throw new Error("The AI-004 result structure was not valid.");
        }

        const value = (item) => String(item ?? "Not reported");
        const status = (passed) => passed ? "PASS" : "NOT CONFIRMED";

        const formatAgentActivity = (agent) => {
            const formatDecision = (item) => {
                const rules = Array.isArray(item.detection_rule_ids)
                    ? item.detection_rule_ids.filter((rule) => typeof rule === "string")
                    : [];
                const fields = [
                    `Memory: ${value(item.memory_id)}`,
                    `Decision: ${value(item.decision)}`,
                    `Integrity: ${value(item.integrity_valid)}`,
                    `Provenance: ${value(item.provenance_valid)}`,
                    `Attestation: ${value(item.attestation_valid)}`,
                    `Injection detected: ${value(item.injection_detected)}`,
                    `Retrieved: ${value(item.retrieved)}`,
                    `Instruction applied: ${value(item.instruction_applied)}`,
                    `Canary indicator: ${value(item.synthetic_canary_exposed)}`,
                    `Response: ${value(item.synthetic_response)}`
                ];
                if (rules.length) {
                    fields.push(`Detection rules: ${rules.join(", ")}`);
                }
                return fields.join(" | ");
            };

            const ingestion = agent.ingestion_decisions.map(formatDecision);
            const retrieval = agent.retrieval_decisions.map(formatDecision);

            return [
                "MEMORY INGESTION",
                ...(ingestion.length ? ingestion : ["No ingestion decisions reported."]),
                "",
                "MEMORY RETRIEVAL",
                ...(retrieval.length ? retrieval : ["No retrieval decisions reported."])
            ].join("\n");
        };

        const expectedEvaluation = [
            evaluation.persistent_instruction_detected === true,
            evaluation.untrusted_provenance_detected === true,
            evaluation.benign_source_attestation_valid === true,
            evaluation.untrusted_source_attestation_valid === true,
            evaluation.tampered_memory_detected === true,
            evaluation.trusted_benign_memory_preserved === true,
            evaluation.poisoned_memory_quarantined === true,
            evaluation.tampered_memory_quarantined === true,
            evaluation.vulnerable_agent_followed_persistent_instruction === true,
            evaluation.secure_agent_followed_persistent_instruction === false,
            evaluation.vulnerable_agent_disclosed_canary === true,
            evaluation.secure_agent_disclosed_canary === false
        ].every(Boolean);

        const noRealSideEffects = (
            result.simulation_only === true
            && result.persisted === false
            && result.real_memory_accessed === false
            && result.real_filesystem_accessed === false
            && result.real_network_requests_sent === false
            && result.real_accounts_modified === false
            && result.external_provider_used === false
        );

        const agentBehaviorValid = (
            vulnerable.stored_count === 3
            && vulnerable.quarantined_count === 0
            && vulnerable.persistent_instructions_followed === 2
            && vulnerable.canary_exposed === true
            && secure.stored_count === 1
            && secure.quarantined_count === 2
            && secure.retrieved_count === 1
            && secure.persistent_instructions_followed === 0
            && secure.canary_exposed === false
        );

        const persistenceValid = hasPersistedHistory(data);

        const passed = (
            expectedEvaluation
            && noRealSideEffects
            && agentBehaviorValid
            && persistenceValid
            && evaluation.blue_team_control === "PASS"
        );

        const overall = byId("ai004-overall-status");
        overall.textContent = passed
            ? "BLUE TEAM CONTROL: PASS"
            : "REVIEW REQUIRED";
        overall.className = passed
            ? "assessment-outcome pass"
            : "assessment-outcome review";

        byId("ai004-execution-type").textContent =
            "Deterministic in-memory mock";
        byId("ai004-interaction-count").textContent =
            value(result.interaction_count);
        byId("ai004-memory-count").textContent =
            value(result.memory_entry_count);
        byId("ai004-audit-status").textContent = persistenceValid
            ? "Audit and assessment history saved"
            : "History save not confirmed";

        const vulnerableState = byId("ai004-vulnerable-state");
        vulnerableState.textContent = vulnerable.persistent_instructions_followed === 2
            ? "POISONED MEMORY FOLLOWED"
            : "BEHAVIOR NOT CONFIRMED";
        vulnerableState.className = vulnerable.persistent_instructions_followed === 2
            ? "result-state unblocked"
            : "result-state";

        const secureState = byId("ai004-secure-state");
        secureState.textContent = secure.quarantined_count === 2
            && secure.persistent_instructions_followed === 0
            ? "UNSAFE MEMORY BLOCKED"
            : "REVIEW REQUIRED";
        secureState.className = secure.quarantined_count === 2
            && secure.persistent_instructions_followed === 0
            ? "result-state blocked"
            : "result-state unblocked";

        byId("ai004-vulnerable-storage").textContent =
            `${value(vulnerable.stored_count)} stored / ${value(vulnerable.quarantined_count)} quarantined`;
        byId("ai004-vulnerable-followed").textContent =
            value(vulnerable.persistent_instructions_followed);
        byId("ai004-vulnerable-canary").textContent =
            vulnerable.canary_exposed === true
                ? "Exposed in vulnerable mock (value redacted)"
                : "No exposure reported";

        byId("ai004-secure-storage").textContent =
            `${value(secure.stored_count)} stored / ${value(secure.quarantined_count)} quarantined`;
        byId("ai004-secure-retrieved").textContent =
            `${value(secure.retrieved_count)} retrieved / ${value(secure.persistent_instructions_followed)} followed`;
        byId("ai004-secure-canary").textContent =
            secure.canary_exposed === false
                ? "Not exposed by protected mock"
                : "Exposure detected or not confirmed";

        byId("ai004-vulnerable-details").textContent =
            formatAgentActivity(vulnerable);
        byId("ai004-secure-details").textContent =
            formatAgentActivity(secure);

        byId("ai004-injection-status").textContent =
            status(evaluation.persistent_instruction_detected === true);
        byId("ai004-provenance-status").textContent =
            status(evaluation.untrusted_provenance_detected === true);
        byId("ai004-attestation-status").textContent =
            evaluation.benign_source_attestation_valid === true
            && evaluation.untrusted_source_attestation_valid === true
                ? "Signatures verified; provenance still checked separately"
                : "NOT CONFIRMED";
        byId("ai004-integrity-status").textContent =
            status(evaluation.tampered_memory_detected === true);
        byId("ai004-benign-status").textContent =
            status(evaluation.trusted_benign_memory_preserved === true);
        byId("ai004-poisoned-status").textContent =
            status(evaluation.poisoned_memory_quarantined === true);
        byId("ai004-tampered-status").textContent =
            status(evaluation.tampered_memory_quarantined === true);
        byId("ai004-persistence-status").textContent =
            evaluation.secure_agent_followed_persistent_instruction === false
                ? "PASS / 0 FOLLOWED"
                : "NOT CONFIRMED";
        byId("ai004-canary-status").textContent =
            evaluation.secure_agent_disclosed_canary === false
                ? "PASS / NOT EXPOSED"
                : "NOT CONFIRMED";
        byId("ai004-side-effects-status").textContent =
            status(noRealSideEffects);
        byId("ai004-controls-status").textContent =
            passed ? "PASS" : "REVIEW REQUIRED";

        byId("ai004-limitations").textContent = Array.isArray(result.limitations)
            ? result.limitations.filter((item) => typeof item === "string").join(" ")
            : "No limitations were reported.";

        byId("ai004-results").hidden = false;
    }

    async function runAI004() {
        const permissions = Array.isArray(currentUser?.permissions)
            ? currentUser.permissions
            : [];

        if (
            !permissions.includes("assessments.execute")
            || !permissions.includes("targets.read")
        ) {
            showFeedback(
                byId("assessment-feedback"),
                "Your account does not have the permissions required to execute this assessment.",
                "error"
            );
            return;
        }

        const confirmed = window.confirm(
            "Run the fixed AI-004 memory-poisoning simulation?\n\n"
            + "It compares vulnerable and protected mock agents across two synthetic interactions.\n"
            + "No real personal memory, database memory, filesystem, network, or external AI provider is accessed. "
            + "A sanitized assessment history and audit event are saved locally; no finding or evidence records are created.\n\n"
            + "Continue?"
        );
        if (!confirmed) return;

        const button = byId("run-ai004-button");
        const label = button.querySelector("span:first-child");
        button.disabled = true;
        label.textContent = "Running controlled simulation...";
        clearFeedback(byId("assessment-feedback"));
        byId("ai004-results").hidden = true;

        try {
            const { data } = await apiRequest("/api/v1/simulations/AI-004/run", {
                method: "POST",
                csrf: true,
                body: {}
            });

            renderAI004Results(data);
            showFeedback(
                byId("assessment-feedback"),
                "AI-004 completed. The sanitized report, assessment history, and audit event were saved locally; no findings or evidence records were created.",
                "info"
            );
            scrollToSimulationResults("ai004-results");
        } catch (error) {
            if (error.status === 401) {
                showLogin();
                return;
            }

            const message = error.status === 403
                ? "Execution was rejected. Check your assessment permissions and authenticated session."
                : error.status === 409
                    ? "Execution was blocked because the training profiles or deterministic mock configuration do not meet the required safety checks."
                    : error.status === 503
                        ? "The local database was unavailable. No successful execution was confirmed."
                        : "AI-004 could not be completed. No successful result was confirmed.";

            showFeedback(byId("assessment-feedback"), message, "error");
        } finally {
            button.disabled = false;
            label.textContent = "Run AI-004 simulation";
        }
    }

    byId("run-ai004-button").addEventListener("click", () => {
        void runAI004();
    });

    window.addEventListener("hashchange", () => {
        if (!byId("workspace").hidden) {
            applyCurrentView();
        }
    });
    async function initialize() {
        byId("auth-loading").hidden = false;
        byId("login-view").hidden = true;
        byId("mfa-view").hidden = true;

        try {
            await loadDashboard();
        } catch {
            showLogin();
        }
    }

    document.addEventListener("DOMContentLoaded", initialize);
})();
