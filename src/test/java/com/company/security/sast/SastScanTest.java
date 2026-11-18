package com.company.security.sast;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.company.security.core.ScanConfig;
import com.company.security.core.ScanResult;
import com.company.security.core.Severity;
import com.company.security.model.Target;
import com.company.security.model.Vulnerability;
import com.company.security.scanners.sast.CheckmarxScanner;
import com.company.security.scanners.sast.SemgrepScanner;
import com.company.security.scanners.sast.SonarQubeScanner;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SastScanTest {

   @Test
    void semgrepOutputIsNormalised() throws Exception {
        String json = """
            {"results":[{"check_id":"java-sql-string-concat","path":"src/Dao.java","start":{"line":42},
              "extra":{"message":"SQL built by concatenation","severity":"ERROR",
                       "metadata":{"cwe":["CWE-89: SQL Injection"]},"fix":"Use PreparedStatement"}}]}
            """;
        List<Vulnerability> v = new SemgrepScanner().parse(json);
        assertThat(v).hasSize(1);
        assertThat(v.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(v.get(0).location()).isEqualTo("src/Dao.java:42");
        assertThat(v.get(0).cwe()).startsWith("CWE-89");
    }

    @Test
    void sonarSeveritiesAreMapped() throws Exception {
        String json = """
            {"issues":[{"rule":"java:S3649","severity":"BLOCKER","message":"SQLi","component":"proj:src/A.java","line":7},
                       {"rule":"java:S2068","severity":"MAJOR","message":"Hard-coded password","component":"proj:src/B.java","line":3}]}
            """;
        List<Vulnerability> v = new SonarQubeScanner().parse(json);
        assertThat(v).extracting(Vulnerability::severity).containsExactly(Severity.CRITICAL, Severity.MEDIUM);
        assertThat(v.get(0).location()).isEqualTo("src/A.java:7");
    }

    @Test
    void checkmarxResultsAreParsedAndNotExploitableSkipped() throws Exception {
        String json = """
            {"results":[
              {"similarityId":"123","severity":"HIGH","state":"TO_VERIFY","description":"XSS",
               "data":{"queryName":"Reflected_XSS","nodes":[{"fileName":"/web/Page.java","line":10}]},
               "vulnerabilityDetails":{"cweId":79}},
              {"similarityId":"124","severity":"HIGH","state":"NOT_EXPLOITABLE","description":"ignored","data":{}}]}
            """;
        List<Vulnerability> v = new CheckmarxScanner().parse(json);
        assertThat(v).hasSize(1);
        assertThat(v.get(0).cwe()).isEqualTo("CWE-79");
    }

    @Test
    void semgrepRunsAgainstSourceWhenInstalled(@TempDir Path tmp) {
        SemgrepScanner scanner = new SemgrepScanner();
        assumeTrue(scanner.isAvailable(), "semgrep not installed - skipping live scan");
        Target target = new Target("self", null, System.getProperty("sast.source", "src/main/java"), null, null, null);
        ScanResult r = scanner.scan(new ScanConfig(target, tmp, Duration.ofMinutes(10),
                Map.of("config", "classpath:rules/semgrep-rules.yaml")));
        assertThat(r.status()).isEqualTo(ScanResult.Status.SUCCESS);
    }
}
