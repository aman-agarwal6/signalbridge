"""Reviewed rule explanations; never render descriptions or links from an import."""

RUFF_GUIDANCE = {
    "S108": {
        "title": "Review a fixed temporary path",
        "explanation": "A temporary-directory path appears in source. Determine whether it creates a predictable shared file or describes a constrained container mount.",
        "why": "Predictable shared temporary paths can let another process replace or read data. A literal used only to verify an isolated mount does not itself create a temporary file.",
        "validate": (
            "Compare the recorded source hash and trace whether the path is opened, written or only used as an inspection key.",
            "For a container mount, check its ownership, namespace, size limit and mount restrictions in a fresh isolation receipt.",
            "For actual temporary files, verify exclusive creation, safe permissions and rejection of links or pre-existing paths.",
        ),
        "remediation": "Use securely created temporary files where files are needed. Preserve explicit mount allowlists where the path is only a validation key; record that distinction instead of suppressing the signal.",
        "unknowns": "The match does not establish a file write, another user's access, a race or exploitability. Host administrators remain trusted in the local lab.",
        "slug": "hardcoded-temp-file",
    },
    "S106": {
        "title": "Review a password embedded in a function call",
        "explanation": "A password-like function argument contains a literal value. Determine whether it is a working credential, a deliberately known local-lab default, or a nonfunctional example. A local default still needs a documented access boundary.",
        "why": "The rule matched a password-like argument in source. A confirmed default password is a real credential weakness within its reachable environment; this result alone does not show that a production secret was exposed.",
        "validate": (
            "Compare the recorded source hash, identify the service and account, and trace the effective connection address without displaying the password.",
            "For the disposable Supabase migration runner, verify its fixed loopback address, rejected connection overrides and a fresh lab isolation check. Loopback does not prevent other local processes from using a known password.",
            "Identify every dependent local service and recovery path before a coordinated change. Verify that a generated replacement works and the old credential fails in the isolated lab; do not test production or another project.",
        ),
        "remediation": "Replace working defaults with generated credentials supplied through private configuration, preserving target restrictions. Coordinate the service and its clients, retain recovery steps, then retest. Moving the same default into a variable or suppressing the rule is not a correction.",
        "unknowns": "The match does not establish the running credential, reachable clients or production exposure. A known lab default requires explicit scope and follow-up; reviewed context is not risk acceptance or proof of remediation.",
        "slug": "hardcoded-password-func-arg",
    },
    "S104": {
        "title": "Review network interface binding",
        "explanation": "A service can accept connections on every interface when it binds to 0.0.0.0. Check which interfaces and ports can reach it, including container port publishing.",
        "why": "The rule detected a hardcoded all-interface address. The code match alone does not establish that a running service is publicly reachable.",
        "validate": (
            "Compare the recorded file hash with the source you intend to review, then inspect the reported line and its callers.",
            "Identify the actual listener, container port publishing and intended audience in the approved local environment.",
            "Document which interfaces can reach the service and the controls that enforce the intended boundary.",
        ),
        "remediation": "Bind to the intended interface and publish only required ports. Where container-internal binding is necessary, document and test the host-side restriction.",
        "unknowns": "Runtime exposure, deployment configuration and the effectiveness of network controls are not established by this lint result.",
        "slug": "hardcoded-bind-all-interfaces",
    },
    "S603": {
        "title": "Review subprocess inputs",
        "explanation": "A process starts without a shell. Check that its executable and arguments come from trusted, bounded inputs. This rule can report safe uses, so inspect the call before deciding.",
        "why": "The rule detected a subprocess call without a shell. It does not determine whether arguments have already been validated and can produce false positives.",
        "validate": (
            "Compare the recorded file hash and inspect the call at the reported line.",
            "Trace executable, arguments, working directory and environment back to their inputs; identify any caller-controlled values.",
            "Use isolated regression tests to prove that disallowed commands and arguments are rejected and required commands still work.",
        ),
        "remediation": "Prefer a fixed executable and an explicit argument list with bounded allowed values. Keep shell execution disabled and record the input trust assumptions.",
        "unknowns": "The report does not prove attacker control, command execution, exploitability or that the call is unsafe.",
        "slug": "subprocess-without-shell-equals-true",
    },
    "S607": {
        "title": "Review executable path selection",
        "explanation": "An executable is selected through the environment's search path. Check that the environment is trusted and whether an explicit executable path would make the choice safer.",
        "why": "The rule detected a partial executable path. Executable selection may depend on the process environment and writable search locations.",
        "validate": (
            "Inspect the recorded source version and determine which executable is intended.",
            "Check who can alter the search path and executable directories for the account running the process.",
            "Test executable selection using an isolated test environment; do not modify the machine-wide search path.",
        ),
        "remediation": "Resolve a trusted executable explicitly where practical and restrict the child environment. Record any necessary dependence on a trusted operator environment.",
        "unknowns": "A partial path does not by itself prove a writable search directory or a successful executable substitution.",
        "slug": "start-process-with-partial-path",
    },
    "S310": {
        "title": "Review URL destinations and schemes",
        "explanation": "A URL-opening function can support schemes beyond HTTP. Check that destinations, redirects, and schemes are constrained before any untrusted input can reach this call.",
        "why": "The rule detected a URL-opening operation that can support unexpected schemes. The finding does not establish which URL values can reach it.",
        "validate": (
            "Inspect the recorded source and trace the URL to its caller or fixed configuration.",
            "Check parsed scheme, host, port and redirect handling, including credentials and alternate address representations.",
            "Use mock requests to verify that disallowed destinations fail before any connection is attempted.",
        ),
        "remediation": "Allow only intended destinations and schemes, refuse unexpected redirects, and bound time and response size. Retest permitted behavior after changing validation.",
        "unknowns": "This report does not prove remote request forgery, local file access or a reachable attacker-controlled URL.",
        "slug": "suspicious-url-open-usage",
    },
}


ZAP_GUIDANCE = {
    "10021": {
        "explanation": "The report says a response lacks X-Content-Type-Options: nosniff. This header asks browsers to respect the declared content type. In this pilot, two pages intentionally omit it and the health page supplies it as a control.",
        "remediation": "For an actual application, set the correct Content-Type and X-Content-Type-Options: nosniff, then retest normal and error responses. The pilot omission is deliberate test data, not a discovered source-app flaw.",
    },
    "10020-1": {
        "explanation": "The report says an HTML response lacks the expected framing protection. Framing rules help control whether another site may embed a page; the actual risk depends on the page's actions and intended embedding behavior.",
        "remediation": "Review intended embedding before setting a suitable Content-Security-Policy frame-ancestors directive or compatible X-Frame-Options policy. Verify legitimate embedding and protected actions after the change.",
    },
    "10038-1": {
        "explanation": "The report says a response lacks an enforced Content Security Policy. A carefully designed policy limits permitted content sources; a missing policy alone does not demonstrate script injection.",
        "remediation": "Define a policy for the application's real scripts, styles and framing requirements, evaluate its effect, and test legitimate behavior before enforcing it. Do not copy a restrictive fixture policy into an application blindly.",
    },
}


def guidance(finding):
    if finding.tool == "ZAP":
        details = {
            "title": finding.title,
            "explanation": "A ZAP JSON report associates this rule with an approved GET path in the disposable SignalBridge lab. Its risk and confidence are tool-reported claims, not a confirmed vulnerability.",
            "why": "The scoped report adapter accepted this rule and path. It discards raw requests, responses, cookies, evidence snippets and report-provided links.",
            "validate": (
                "Verify the separate execution record, target identity and scan configuration before relying on this report.",
                "Review the rule in official ZAP documentation and reproduce the observation only against the approved disposable target.",
                "Check the application's intended headers or behavior, then retest both the reported condition and legitimate access after a correction.",
            ),
            "remediation": "Apply a context-appropriate correction to the isolated target after validating the observation. A passive web report does not replace authorization testing.",
            "unknowns": "Imported JSON cannot prove scanner execution, redirects followed, requests omitted, authenticated coverage or exploitability. No source-file location is inferred from a web path.",
            "url": "https://www.zaproxy.org/docs/alerts/",
            "url_title": "Read the official ZAP alert catalogue",
            "level_label": "Reported ZAP risk",
            "kind": "Web report signal",
        }
        if finding.rule_id in ZAP_GUIDANCE:
            details.update(ZAP_GUIDANCE[finding.rule_id])
            details["url"] = "https://www.zaproxy.org/docs/alerts/" + finding.rule_id + "/"
            details["url_title"] = "Read the official ZAP rule"
        return details
    if finding.tool.casefold() == "ruff" and finding.rule_id in RUFF_GUIDANCE:
        item = RUFF_GUIDANCE[finding.rule_id]
        return {
            **item,
            "url": "https://docs.astral.sh/ruff/rules/" + item["slug"] + "/",
            "url_title": "Read the official Ruff rule",
            "level_label": "Reported SARIF level",
            "kind": "Static code signal",
        }
    if finding.tool.casefold() == "pip-audit":
        return {
            "title": f"Review {finding.package} advisory {finding.rule_id}",
            "explanation": "The report associates this package version with an advisory. Check the advisory's affected conditions and whether this application uses the affected behavior.",
            "why": "pip-audit reported an advisory identifier for the supplied package name and version. This is a dependency observation, not an exploitation test.",
            "validate": (
                "Verify the recorded requirements manifest and the package version actually used by the environment being reviewed.",
                "Inspect the advisory using the package maintainer's or advisory publisher's trusted documentation; do not trust report-provided links.",
                "Check applicability, review the suggested release changes and test an upgrade in an isolated environment before changing a running application.",
            ),
            "remediation": "Use an applicable supported fixed version when available and verify compatibility. If a fix is unavailable, document a scoped mitigation or an explicit risk decision with a follow-up review date.",
            "unknowns": "Severity, exploitability, deployed versions and transitive dependency coverage are not established here. Listed fixes are scanner suggestions, not verified upgrades.",
            "url": "https://github.com/pypa/pip-audit#security-model",
            "url_title": "Read pip-audit's documented limitations",
            "level_label": "Vulnerability severity",
            "kind": "Dependency advisory signal",
        }
    return {
        "title": finding.title,
        "explanation": "Inspect the reported rule and affected source or package. Validate the observation in its actual context before recording a disposition.",
        "why": "An imported scanner reported this rule identifier. No reviewed rule-specific explanation is available in SignalBridge.",
        "validate": (
            "Establish who produced the report, the tool version and the exact inputs it inspected.",
            "Use trusted tool documentation to understand the rule and review the affected source or dependency in an isolated environment.",
            "Record reproducible validation and any remaining unknowns before choosing a disposition.",
        ),
        "remediation": "Choose a context-specific correction after validating the observation, then rerun the relevant checks on the corrected source.",
        "unknowns": "Tool execution, source coverage, exploitability and severity require independent validation. Report content is an untrusted claim.",
        "url": "",
        "url_title": "",
        "level_label": "Reported SARIF level",
        "kind": "Scanner signal",
    }


def run_guidance(run):
    local = run.provenance == "local_execution"
    if run.format == "zap":
        return {
            "scope": "Imported fixed-lab report for SignalBridge: GET /, /login/ and /health/ only. Actual requests and authentication are not established by this file.",
            "trust": "Unverified imported claim",
            "currentness": "Runtime target and source identity were not verified by this import.",
            "limit": "Coverage remains unknown, even for an empty report. Zero recorded input count means the report does not prove how many requests ran; it does not mean zero requests executed.",
        }
    if not local:
        scope = "Imported report only; no locally verified source manifest or execution."
    elif run.format == "pip-audit":
        scope = f"{run.input_count} explicit dependency entries; requirements.txt is the recorded input."
    else:
        scope = f"{len(run.manifest)} source files are recorded in this run's manifest."
    return {
        "scope": scope,
        "trust": "Local execution recorded" if local else "Unverified imported claim",
        "currentness": "Current checkout not compared; rerun after source or dependency changes.",
        "limit": (
            "The fixed audit covers explicit public package pins only; transitive, development, npm and deployed dependencies are outside this run."
            if local and run.format == "pip-audit"
            else "Only the recorded inputs and selected rules are covered; absence of a finding does not prove a correction or an absence of vulnerabilities."
        ),
    }


def observation_guidance(observation):
    if observation is None:
        return {"available": False, "trust": "No observation recorded"}
    run = observation.scan_run
    return {
        **run_guidance(run),
        "available": True,
        "run_id": str(run.pk),
        "source_file_digest": run.manifest.get(observation.path, ""),
        "requirements_digest": run.manifest.get("requirements.txt", ""),
        "source_revision": run.source_revision,
        "report_digest": run.digest,
        "suppressed": observation.suppressed,
        "suppression_statuses": observation.suppression_statuses,
        "coverage_status": run.coverage_status,
        "created_at": run.created_at,
    }
