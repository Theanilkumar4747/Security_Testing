# Security Automation Framework

A Java 17 / Maven framework that runs **SAST, SCA, DAST, API, secrets and cloud/IaC scanners** from one
command, normalises every tool's output into a common model, produces HTML / JSON / SARIF reports, enforces a
**quality gate** that fails CI, and pushes results to Jira, Slack, e-mail, DefectDojo and a dashboard.

> **Authorised use only.** DAST and API scanners send real traffic. They run only against hosts listed in
> `scan.allowed.hosts` (default: `localhost,127.0.0.1`) and refuse everything else. Only scan systems you own
> or have written permission to test. ZAP `mode: full` is an *active attack* - use it on staging, never production.

## How it works

```
CLI / CI ──> ScanOrchestrator ──> ParallelScanExecutor ──> Scanners (SAST|SCA|DAST|API|SECRETS|CLOUD)
                                          │                         (each wraps a tool, returns ScanResult)
                                          ▼
                                     ScanReport ──> ReportGenerator (HTML/JSON/SARIF) ──> DashboardPublisher
                                          │
                                          ├──> QualityGate (thresholds + suppressions) ──> BuildBreaker (exit code)
                                          └──> Jira / Slack / Email / DefectDojo
```

## Quick start

```bash
mvn clean verify                       # build + unit tests (no external tools needed)

# Static scans of the current repo
java -jar target/security-framework.jar --categories=SAST,SCA,SECRETS,CLOUD --source=.

# Pick scanners explicitly
java -jar target/security-framework.jar --scanners=semgrep,trivy,gitleaks

# Dynamic scan of a staging system you own
SCAN_ALLOWED_HOSTS=staging.example.com \
java -jar target/security-framework.jar --scanners=zap,owasp-api-top10 --url=https://staging.example.com

# Passive ZAP baseline scan of the configured login page (Docker required)
java -jar target/security-framework.jar --scanners=zap --no-publish

# Nightly schedule inside one long-running process
java -jar target/security-framework.jar --categories=SCA --schedule-hours=24
```

Reports land in `target/security-reports/` (`security-report.html|json|sarif`, `gate-result.json`, `raw/<scanner>/`).
The HTML report is a self-contained dashboard with scanner outcomes, finding charts, quality-gate verdict, stable finding IDs,
severity/status/scanner filters, and expandable remediation tracking (status, owner, due date, and retest result). Tracking is
saved in the browser for the same target; use **Export tracker JSON** and **Import tracker JSON** to back up or transfer it.
API findings include HTTP method and observed security-header evidence where available. Sensitive token, cookie, password,
and authorization values are redacted in the HTML output. Other scanner evidence fields show the parser's available data;
the report labels missing values rather than inventing evidence.
Framework action logs are written to `target/security-reports/framework.log` and rotated by size/date.

**Exit codes:** `0` gate passed · `1` gate failed · `2` configuration/runtime error.

### CLI flags
`--name --url --source --image --spec --iac --out --config --gate-config --formats --scanners --categories --no-gate --no-publish --schedule-hours`

## Scanners and the tools they need

Scanners whose tool is missing are **skipped** (not failed), so you can adopt tools incrementally.

| Category | Scanner class | Tool required on PATH / service |
|---|---|---|
| SAST | `SemgrepScanner` | `semgrep` |
| SAST | `SonarQubeScanner` | `sonar-scanner` + server, `SONAR_TOKEN` |
| SAST | `CheckmarxScanner` | `cx` CLI, `CX_CLIENT_ID/SECRET/BASE_URI` |
| SCA | `TrivyScanner` | `trivy` |
| SCA | `OWASPDependencyCheckScanner` | `dependency-check.sh`, optional `NVD_API_KEY` |
| SCA | `SnykScanner` | `snyk`, `SNYK_TOKEN` |
| DAST | `ZAPScanner` | Docker (official ZAP image) |
| DAST | `NucleiScanner` | `nuclei` |
| DAST | `BurpScanner` | Running Burp Pro with REST API (`BURP_API_URL`, `BURP_API_KEY`) |
| API | `RestAssuredSecurityTests` | none (built in) |
| API | `OwaspApiTop10Checks` | none; `API_TOKEN_A` / `API_TOKEN_B` for authz checks |
| API | `SchemathesisRunner` | `schemathesis` + OpenAPI spec (`--spec`) |
| Secrets | `GitleaksScanner` | `gitleaks` (findings are redacted) |
| Secrets | `TruffleHogScanner` | `trufflehog` |
| Cloud | `CheckovScanner` | `checkov` |
| Cloud | `KubeBenchScanner` | `kube-bench` (run on the node) |
| Cloud | `ProwlerScanner` | `prowler` + cloud credentials |

`OwaspApiTop10Checks` maps to the OWASP API Security Top 10 (2023): API1 BOLA, API2 broken auth (incl. `alg=none` JWT),
API3 excessive data exposure, API4 rate limiting, API5 BFLA, API8 misconfiguration, API9 inventory.

## Configuration

| File | Purpose |
|---|---|
| `config/application.properties` | Global settings, allowed hosts, integrations on/off |
| `config/scanners-config.yaml` | Which scanners are enabled, timeouts, per-scanner options |
| `config/quality-gate.yaml` | Severity thresholds, per-category limits, suppressions with expiry |
| `rules/semgrep-rules.yaml` | Custom Semgrep rules (extracted at runtime via `classpath:`) |
| `rules/zap-rules.tsv` | ZAP rule actions (IGNORE / WARN / FAIL) |
| `log4j2.xml` | Logging |

Any property can be overridden by environment variable (`scan.allowed.hosts` -> `SCAN_ALLOWED_HOSTS`) or `-Dkey=value`.
To use external config files: `--config=my-scanners.yaml`, `--gate-config=my-gate.yaml`, or `SECURITY_CONFIG_FILE=/path/app.properties`.
**Secrets are read from the environment only.**

### Quality gate
```yaml
gate:
  maxAllowed: {CRITICAL: 0, HIGH: 0, MEDIUM: 25, LOW: -1}
  perCategory:
    SECRETS: {CRITICAL: 0, HIGH: 0, MEDIUM: 0}
  suppressions:
    - id: CVE-2024-12345
      expires: 2026-12-31          # expired suppressions stop applying automatically
      reason: "Not reachable, see SEC-123"
```

### Integrations (enable in `application.properties` or env)
| Integration | Enable | Settings |
|---|---|---|
| Slack | `integration.slack.enabled=true` | `SLACK_WEBHOOK_URL` |
| Email | `integration.email.enabled=true` | `smtp.host`, `smtp.port`, `SMTP_USER`, `SMTP_PASSWORD`, `email.from`, `email.to` |
| Jira | `integration.jira.enabled=true` | `jira.url`, `jira.user`, `JIRA_TOKEN`, `jira.project`; Jira Cloud: `jira.search.path=/rest/api/3/search/jql` |
| DefectDojo | `integration.defectdojo.enabled=true` | `defectdojo.url`, `DEFECTDOJO_TOKEN` (uploads SARIF) |
| Dashboard | `dashboard.type=filesystem\|http` | `dashboard.dir` or `dashboard.url` + `DASHBOARD_TOKEN` |

Integration failures are logged but never change the scan verdict.

## Adding a scanner
1. Create a class extending `BaseScanner` in the right `scanners/<category>/` package. Implement `name()`, `category()`,
   `execute()` (run the tool, return raw output) and `parse()` (raw -> `List<Vulnerability>`).
2. Register it in `ScanOrchestrator.REGISTRY` and add an entry to `scanners-config.yaml`.
3. Add a parser test with sample output (see `SastScanTest`).

## Tests
`mvn test` runs parser tests, an in-process weak API server for the API checks, and gate/SARIF regression tests.
Live-tool tests skip themselves when the tool is absent (`-Dsast.source=...`, `-Ddast.target=http://localhost:8080`).

`BsscApiContractTest` records the 13 endpoints from the supplied HAR and checks their methods, captured status
codes, JSON responses, and an unknown-route negative case against a local in-process fixture. It does not send
traffic to the captured BSSC host. The request schemas and authentication flow payloads were not present in the
inventory, so no request bodies or live OTP/payment operations are fabricated. Use only a separately authorized
staging environment when adding integration tests for those flows. API security findings can be included in the
framework's existing HTML, JSON, and SARIF reports by enabling the API scanners.

## CI
* `.github/workflows/security.yml` - static scans on every push/PR + nightly, SARIF upload to code scanning, optional staging DAST job.
* `Jenkinsfile` - parameterised pipeline with report archiving and HTML publishing.

## Notes
* Written against current CLI flags of each tool (Semgrep, Trivy, Gitleaks, Checkov, Prowler v4+, Schemathesis v4, ZAP, Nuclei).
  Tool CLIs change; if a flag breaks after an upgrade, adjust the command in that scanner's `execute()`.
* Layout addition vs. the original spec: `utils/HttpUtil.java` (shared HTTP helper).
