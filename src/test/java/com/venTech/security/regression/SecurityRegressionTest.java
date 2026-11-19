package com.venTech.security.regression;

import static org.assertj.core.api.Assertions.assertThat;

import com.venTech.security.core.ScanResult;
import com.venTech.security.core.ScannerInterface.Category;
import com.venTech.security.core.Severity;
import com.venTech.security.gate.QualityGate;
import com.venTech.security.model.ScanReport;
import com.venTech.security.model.Target;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.reporting.HtmlReportBuilder;
import com.venTech.security.reporting.SarifReportBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Guards the behaviour CI depends on: quality-gate decisions, suppressions and SARIF output. */
class SecurityRegressionTest {

    private static final String GATE = """
        gate:
          maxAllowed: {CRITICAL: 0, HIGH: 1, MEDIUM: -1}
          perCategory:
            SECRETS: {HIGH: 0}
          suppressions:
            - id: CVE-2024-0001
              expires: 2999-01-01
            - id: CVE-2020-0002
              expires: 2020-01-01
        """;

    private static Vulnerability vuln(String id, Severity sev, Category cat, String cve) {
        return Vulnerability.builder().id(id).title("t-" + id).description("Description for " + id)
                .severity(sev).scanner("test").category(cat).location("src/App.java:10")
                .cve(cve).remediation("Fix " + id).evidence("Observed evidence for " + id)
                .expectedResult("Expected secure behavior").actualResult("Observed insecure behavior").build();
    }

    private static ScanReport report(Vulnerability... vs) {
        ScanResult r = ScanResult.success("test", Category.SCA, List.of(vs), 1);
        return new ScanReport("r1", Instant.now(), Instant.now(), new Target("app", null, ".", null, null, null), List.of(r));
    }

    @Test
    void passesWithinThresholds() throws Exception {
        var res = QualityGate.fromYaml(GATE).evaluate(report(vuln("A", Severity.HIGH, Category.SCA, null)));
        assertThat(res.passed()).isTrue();
    }

    @Test
    void failsOnAnyCritical() throws Exception {
        var res = QualityGate.fromYaml(GATE).evaluate(report(vuln("A", Severity.CRITICAL, Category.SAST, null)));
        assertThat(res.passed()).isFalse();
        assertThat(res.violations()).anyMatch(v -> v.contains("CRITICAL"));
    }

    @Test
    void failsOnSecretsEvenWhenGlobalLimitAllowsIt() throws Exception {
        var res = QualityGate.fromYaml(GATE).evaluate(report(vuln("leak", Severity.HIGH, Category.SECRETS, null)));
        assertThat(res.passed()).isFalse();
        assertThat(res.violations()).anyMatch(v -> v.startsWith("SECRETS"));
    }

    @Test
    void activeSuppressionIsHonoured() throws Exception {
        var res = QualityGate.fromYaml(GATE).evaluate(report(vuln("X", Severity.CRITICAL, Category.SCA, "CVE-2024-0001")));
        assertThat(res.passed()).isTrue();
        assertThat(res.suppressed()).isEqualTo(1);
    }

    @Test
    void expiredSuppressionNoLongerApplies() throws Exception {
        var res = QualityGate.fromYaml(GATE).evaluate(report(vuln("X", Severity.CRITICAL, Category.SCA, "CVE-2020-0002")));
        assertThat(res.passed()).isFalse();
    }

    @Test
    void sarifOutputIsWellFormed() {
        JsonNode sarif = new SarifReportBuilder().buildNode(report(vuln("RULE-1", Severity.HIGH, Category.SAST, null)));
        assertThat(sarif.path("version").asText()).isEqualTo("2.1.0");
        JsonNode result = sarif.path("runs").path(0).path("results").path(0);
        assertThat(result.path("ruleId").asText()).isEqualTo("RULE-1");
        assertThat(result.path("level").asText()).isEqualTo("error");
        assertThat(result.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(10);
        assertThat(result.at("/locations/0/physicalLocation/artifactLocation/uri").asText()).isEqualTo("src/App.java");
    }

    @Test
    void htmlReportShowsExecutionSummaryAndGateVerdict() {
        ScanReport base = report(vuln("RULE-1", Severity.HIGH, Category.SAST, null));
        ScanReport scan = new ScanReport(base.id(), base.startedAt(), base.finishedAt(),
                new Target("<script>app</script>", null, ".", null, null, null), base.results());
        var gate = new QualityGate.GateResult(false, List.of("overall HIGH limit exceeded"), scan.countBySeverity(), 0);

        String html = new HtmlReportBuilder().build(scan, gate);

        assertThat(html).contains("Security Scan Report", "Visual summary", "Findings by severity",
                "Findings by scanner", "aria-label=\"Bar chart of findings by severity\"",
                "How to read this report", "Start here: highest-priority fixes", "Why it matters:",
                "Suggested fix:", "Search findings", "finding-search", "Execution details", "SCA",
                "Quality gate", "overall HIGH limit exceeded", "Description for RULE-1", "Fix RULE-1",
                "Finding ID", "Vulnerability", "Severity", "Endpoint", "Evidence", "Observed evidence for RULE-1",
                "Expected result", "Expected secure behavior", "Actual result", "Observed insecure behavior",
                "Recommendation", "Status", "Open", "F-", "data-tracker-scope", "Export tracker JSON",
                "Import tracker JSON", "filter-severity", "filter-status", "filter-scanner",
                "data-field=\"owner\"", "data-field=\"dueDate\"", "data-field=\"retest\"",
                "Accepted Risk", "targetScope", "localStorage", "RULE-1", "FAILED",
                "&lt;script&gt;app&lt;/script&gt;");
        assertThat(html).doesNotContain("<script>app</script>");
    }

    @Test
    void htmlReportRedactsCredentialsInFindingDetails() {
        Vulnerability sensitive = Vulnerability.builder().id("API-SECRET")
                .title("Credential exposure").severity(Severity.HIGH).scanner("test").category(Category.API)
                .location("https://pp-dev.veportal.in/client/dashboard?access_token=secret-query-value")
                .description("Authorization: Bearer abcdef1234567890token password=hunter2; Cookie: session=hidden; theme=dark")
                .evidence("id_token_hint=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue")
                .description("Authorization: Bearer abcdef1234567890token password=hunter2; Cookie: session=hidden; theme=dark")
                .evidence("id_token_hint=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue")
                .remediation("Rotate credentials and remove them from URLs").build();
        String html = new HtmlReportBuilder().build(report(sensitive));
        assertThat(html).contains("[REDACTED]");
        assertThat(html).doesNotContain("secret-query-value", "abcdef1234567890token", "hunter2",
                "eyJhbGciOiJIUzI1NiJ9", "session=hidden", "theme=dark");
    }
}
