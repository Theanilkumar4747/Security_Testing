package com.venTech.security.dast;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.ScanResult;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Target;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.scanners.dast.NucleiScanner;
import com.venTech.security.scanners.dast.SeleniumDashboardScanner;
import com.venTech.security.scanners.dast.ZAPScanner;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DastScanTest {

    @Test
    void zapAlertsAreNormalised() throws Exception {
        String json = """
            {"site":[{"@name":"http://localhost:8080","alerts":[
              {"pluginid":"10020","alert":"Missing Anti-clickjacking Header","riskcode":"2",
               "desc":"<p>The response does not protect against clickjacking.</p>","solution":"<p>Set X-Frame-Options</p>",
               "cweid":"1021","instances":[{"uri":"http://localhost:8080/"}]},
              {"pluginid":"40018","alert":"SQL Injection","riskcode":"3","desc":"<p>SQLi</p>","cweid":"89",
               "instances":[{"uri":"http://localhost:8080/search"}]}]}]}
            """;
        List<Vulnerability> v = new ZAPScanner().parse(json);
        assertThat(v).extracting(Vulnerability::severity).containsExactly(Severity.MEDIUM, Severity.HIGH);
        assertThat(v.get(0).description()).doesNotContain("<p>");
        assertThat(v.get(1).cwe()).isEqualTo("CWE-89");
    }

    @Test
    void nucleiJsonLinesAreParsed() throws Exception {
        String jsonl = "{\"template-id\":\"exposed-env\",\"info\":{\"name\":\"Exposed .env\",\"severity\":\"high\","
                + "\"classification\":{\"cwe-id\":[\"CWE-200\"]}},\"matched-at\":\"http://localhost/.env\"}\n";
        List<Vulnerability> v = new NucleiScanner().parse(jsonl);
        assertThat(v).hasSize(1);
        assertThat(v.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(v.get(0).location()).isEqualTo("http://localhost/.env");
    }

    @Test
    void seleniumLoginSqlErrorsAreReportedAsHighSeverityFindings() throws Exception {
        String raw = """
                {
                  "url": "https://pp-dev.veportal.in/client/dashboard",
                  "sqlInjectionTested": true,
                  "sqlInjectionLocation": "https://pp-dev.veportal.in/login",
                  "sqlInjectionError": "SQL syntax error near input"
                }
                """;

        List<Vulnerability> findings = new SeleniumDashboardScanner().parse(raw);

        assertThat(findings).extracting(Vulnerability::id).contains("SELENIUM-SQLI-ERROR");
        Vulnerability finding = findings.stream()
                .filter(v -> "SELENIUM-SQLI-ERROR".equals(v.id())).findFirst().orElseThrow();
        assertThat(finding.severity()).isEqualTo(Severity.HIGH);
        assertThat(finding.location()).isEqualTo("https://pp-dev.veportal.in/login");
    }

    @Test
    void seleniumReportsLoginProbeLocationWhenNoDatabaseErrorIsDetected() throws Exception {
        String raw = """
                {
                  "url": "https://pp-dev.veportal.in/client/dashboard",
                  "sqlInjectionTested": true,
                  "sqlInjectionLocation": "https://pp-dev.veportal.in/login",
                  "sqlInjectionError": null
                }
                """;

        List<Vulnerability> findings = new SeleniumDashboardScanner().parse(raw);

        Vulnerability result = findings.stream()
                .filter(v -> "SELENIUM-SQLI-CHECKED".equals(v.id())).findFirst().orElseThrow();
        assertThat(result.severity()).isEqualTo(Severity.INFO);
        assertThat(result.location()).isEqualTo("https://pp-dev.veportal.in/login");
        assertThat(result.description()).contains("does not prove");
    }

    @Test
    void seleniumReportClearlyListsCombinedLoginCasesAsNotRun() throws Exception {
        String raw = """
                {
                  "url": "https://pp-dev.veportal.in/client/dashboard",
                  "sqlInjectionLocation": "https://pp-dev.veportal.in/login",
                  "sqlLoginCases": [
                    {"id": "SQL_LOGIN_001", "status": "NOT_RUN"},
                    {"id": "SQL_LOGIN_010", "status": "NOT_RUN"}
                  ]
                }
                """;

        List<Vulnerability> findings = new SeleniumDashboardScanner().parse(raw);

        Vulnerability scope = findings.stream()
                .filter(v -> "SELENIUM-SQLI-SCOPE".equals(v.id())).findFirst().orElseThrow();
        assertThat(scope.location()).isEqualTo("https://pp-dev.veportal.in/login");
        assertThat(scope.evidence()).contains("SQL_LOGIN_001", "SQL_LOGIN_010");
        assertThat(scope.actualResult()).contains("Not executed");
    }

    @Test
    void dynamicScannersRefuseUnlistedHosts(@TempDir Path tmp) {
        System.setProperty("scan.allowed.hosts", "localhost");
        try {
            Target evil = new Target("t", "http://pp-dev-no-access.veportal.in", ".", null, null, null);
            ScanResult r = new ZAPScanner().scan(new ScanConfig(evil, tmp, Duration.ofMinutes(1), Map.of()));
            assertThat(r.status()).isEqualTo(ScanResult.Status.FAILED);
            assertThat(r.message()).contains("not authorised");
        } finally {
            System.clearProperty("scan.allowed.hosts");
        }
    }

    /** Live scan: run with -Ddast.target=http://localhost:8080 (and Docker available). */
    @Test
    void zapBaselineAgainstLocalTarget(@TempDir Path tmp) {
        String url = System.getProperty("dast.target");
        ZAPScanner zap = new ZAPScanner();
        assumeTrue(url != null && zap.isAvailable(), "set -Ddast.target and install Docker to run the live ZAP scan");
        System.setProperty("scan.allowed.hosts", java.net.URI.create(url).getHost());
        try {
            ScanResult r = zap.scan(new ScanConfig(new Target("live", url, ".", null, null, null), tmp,
                    Duration.ofMinutes(20), Map.of("mode", "baseline", "network", "host")));
            assertThat(r.status()).isEqualTo(ScanResult.Status.SUCCESS);
        } finally {
            System.clearProperty("scan.allowed.hosts");
        }
    }
}
