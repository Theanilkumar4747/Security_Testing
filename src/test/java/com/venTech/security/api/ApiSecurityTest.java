package com.venTech.security.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.ScanResult;
import com.venTech.security.model.Target;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.scanners.api.OwaspApiTop10Checks;
import com.venTech.security.scanners.api.RestAssuredSecurityTests;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Runs the API checks against a deliberately weak in-process server so the tests are deterministic. */
class ApiSecurityTest {
    private HttpServer server;
    private Target target;
    @TempDir Path tmp;

    @BeforeEach
    void startWeakServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            byte[] body = "{\"id\":1,\"name\":\"alice\",\"password\":\"hunter2\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.getResponseHeaders().add("Server", "Apache/2.2.8 (Ubuntu)");
            ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        });
        server.start();
        System.setProperty("scan.allowed.hosts", "127.0.0.1");
        target = new Target("weak", "http://127.0.0.1:" + server.getAddress().getPort(), ".", null, null, null);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        System.clearProperty("scan.allowed.hosts");
    }

    @Test
    void owaspChecksFlagAuthExposureAndRateLimitIssues() {
        ScanConfig cfg = new ScanConfig(target, tmp, Duration.ofMinutes(1),
                Map.of("protectedPaths", "/api/users/1", "rateLimitPath", "/api/users/1", "burst", "25"));
        ScanResult r = new OwaspApiTop10Checks().scan(cfg);
        assertThat(r.status()).isEqualTo(ScanResult.Status.SUCCESS);
        assertThat(r.vulnerabilities()).extracting(Vulnerability::id).contains(
                "API2:2023-NO-AUTH", "API2:2023-INVALID-TOKEN", "API2:2023-JWT-ALG-NONE",
                "API3:2023-EXCESSIVE-DATA", "API4:2023-NO-RATE-LIMIT");
    }

    @Test
    void httpHardeningChecksFlagHeadersBannerAndCors() {
        ScanConfig cfg = new ScanConfig(target, tmp, Duration.ofMinutes(1), Map.of("paths", "/"));
        ScanResult r = new RestAssuredSecurityTests().scan(cfg);

        assertThat(r.status()).isEqualTo(ScanResult.Status.SUCCESS);
        assertThat(r.vulnerabilities()).extracting(Vulnerability::id).contains(
                "API-HDR-NOSNIFF", "API-BANNER-SERVER", "API-CORS");
        Vulnerability missingNosniff = r.vulnerabilities().stream()
                .filter(v -> "API-HDR-NOSNIFF".equals(v.id())).findFirst().orElseThrow();
        assertThat(missingNosniff.httpMethod()).isEqualTo("GET");
        assertThat(missingNosniff.evidence()).contains("X-Content-Type-Options response header: missing");
        assertThat(missingNosniff.expectedResult()).contains("X-Content-Type-Options: nosniff");
        assertThat(missingNosniff.actualResult()).contains("missing");
        assertThat(missingNosniff.status()).isEqualTo("Open");
    }

    @Test
    void unlistedHostIsRefused() {
        System.setProperty("scan.allowed.hosts", "pp-dev-no-access.veportal.in");
        ScanResult r = new OwaspApiTop10Checks().scan(new ScanConfig(target, tmp, Duration.ofMinutes(1), Map.of()));
        assertThat(r.status()).isEqualTo(ScanResult.Status.FAILED);
    }
}
