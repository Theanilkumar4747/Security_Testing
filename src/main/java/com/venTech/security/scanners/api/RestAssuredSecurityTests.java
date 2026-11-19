package com.venTech.security.scanners.api;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Non-destructive HTTP security checks: security headers, banner leakage, CORS, dangerous methods,
 * unauthenticated access, verbose errors and SQL-error reflection. Only sends benign probes.
 */
public class RestAssuredSecurityTests extends BaseScanner {

    static {
        RestAssured.config = RestAssuredConfig.config().httpClient(HttpClientConfig.httpClientConfig()
                .setParam("http.connection.timeout", 10_000).setParam("http.socket.timeout", 20_000));
    }

    private static final Pattern VERSIONED_BANNER = Pattern.compile(".*\\d+\\.\\d+.*");
    private static final List<String> ERROR_SIGNATURES = List.of("stack trace", "exception in thread", "traceback (most recent",
            "at com.", "at org.", "at java.", "nullpointerexception");
    private static final List<String> SQL_SIGNATURES = List.of("sql syntax", "sqlexception", "ora-0", "psqlexception",
            "sqlite error", "odbc driver", "unclosed quotation mark");

    @Override public String name() { return "restassured-security-tests"; }
    @Override public Category category() { return Category.API; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception { return toRaw(runChecks(cfg)); }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception { return fromRaw(raw); }

    /** Package-visible so OwaspApiTop10Checks can reuse the same request setup. */
    static RequestSpecification spec(ScanConfig cfg, String bearer) {
        RequestSpecification s = RestAssured.given().baseUri(cfg.target().url()).redirects().follow(false);
        if (cfg.option("insecureTls", "false").equals("true")) s = s.relaxedHTTPSValidation();
        if (bearer != null && !bearer.isBlank()) s = s.header("Authorization", "Bearer " + bearer);
        return s;
    }

    static Vulnerability finding(String id, String title, Severity sev, String where, String desc, String fix) {
        return finding(id, title, sev, where, desc, fix, "GET");
    }

    static Vulnerability finding(String id, String title, Severity sev, String where, String desc, String fix,
                                 String method) {
        return Vulnerability.builder().id(id).title(title).severity(sev).scanner("restassured-security-tests")
                .category(Category.API).location(where).description(desc).evidence(desc).httpMethod(method)
                .expectedResult("The endpoint should enforce the security control described by the finding")
                .actualResult(desc).remediation(fix).build();
    }

    private static Vulnerability headerFinding(String id, String title, Severity severity, String where,
                                               String evidence, String expected, String actual, String fix,
                                               String actualHeader) {
        String observedHeader = actualHeader == null ? "missing" : actualHeader;
        return Vulnerability.builder().id(id).title(title).severity(severity).scanner("restassured-security-tests")
                .category(Category.API).location(where).description(evidence)
                .evidence(evidence + "; observed response header: " + observedHeader)
                .expectedResult(expected).actualResult(actual + "; observed response header: " + observedHeader)
                .remediation(fix).httpMethod("GET").build();
    }

    public List<Vulnerability> runChecks(ScanConfig cfg) {
        List<Vulnerability> out = new ArrayList<>();
        List<String> paths = cfg.listOption("paths", "/");
        String base = cfg.target().url();

        for (String path : paths) {
            Response r = spec(cfg, null).get(path);
            checkHeaders(base, path, r, out);

            Response cors = spec(cfg, null).header("Origin", "https://pp-dev-no-access.veportal.in").get(path);
            String acao = cors.getHeader("Access-Control-Allow-Origin");
            boolean creds = "true".equalsIgnoreCase(cors.getHeader("Access-Control-Allow-Credentials"));
            if ("https://pp-dev-no-access.veportal.in".equals(acao) || "*".equals(acao)) {
                Severity sev = creds ? Severity.HIGH : ("*".equals(acao) ? Severity.LOW : Severity.MEDIUM);
                out.add(finding("API-CORS", "Permissive CORS policy", sev, base + path,
                        "Access-Control-Allow-Origin returned '" + acao + "' for an untrusted origin"
                                + (creds ? " with credentials allowed" : ""),
                        "Restrict allowed origins to an explicit allow-list"));
            }
            Response trace = spec(cfg, null).request("TRACE", path);
            if (trace.statusCode() == 200) {
                out.add(finding("API-TRACE", "HTTP TRACE enabled", Severity.MEDIUM, base + path,
                        "TRACE returned 200", "Disable TRACE on the web server / gateway", "TRACE"));
            }
        }

        for (String path : cfg.listOption("protectedPaths", "")) {
            int sc = spec(cfg, null).get(path).statusCode();
            if (sc >= 200 && sc < 300) {
                out.add(finding("API-UNAUTH-ACCESS", "Protected endpoint accessible without credentials", Severity.HIGH,
                        base + path, "GET returned HTTP " + sc + " with no Authorization header",
                        "Enforce authentication on every non-public route"));
            }
        }

        String errorPath = cfg.option("errorPath", "");
        if (!errorPath.isBlank()) {
            Response r = spec(cfg, null).contentType("application/json").body("{\"malformed\":").post(errorPath);
            String body = r.getBody().asString().toLowerCase(Locale.ROOT);
            if (ERROR_SIGNATURES.stream().anyMatch(body::contains)) {
                out.add(finding("API-VERBOSE-ERROR", "Verbose error / stack trace disclosure", Severity.MEDIUM, base + errorPath,
                        "Malformed input produced an error body containing implementation details",
                        "Return generic error messages; log details server-side", "POST"));
            }
        }

        String probePath = cfg.option("probePath", "");
        if (!probePath.isBlank()) {
            Response r = spec(cfg, null).queryParam("id", "'").get(probePath);
            String body = r.getBody().asString().toLowerCase(Locale.ROOT);
            if (SQL_SIGNATURES.stream().anyMatch(body::contains)) {
                out.add(finding("API-SQL-ERROR", "Database error reflected in response", Severity.HIGH, base + probePath,
                        "A single quote in a parameter produced a database error message (possible SQL injection)",
                        "Use parameterised queries and suppress database errors"));
            }
        }
        return out;
    }

    private void checkHeaders(String base, String path, Response r, List<Vulnerability> out) {
        String where = base + path;
        if (base.startsWith("https") && r.getHeader("Strict-Transport-Security") == null) {
            out.add(headerFinding("API-HDR-HSTS", "Missing Strict-Transport-Security", Severity.MEDIUM, where,
                    "Response did not include Strict-Transport-Security",
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains", "Header missing",
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    r.getHeader("Strict-Transport-Security")));
        }
        String nosniff = r.getHeader("X-Content-Type-Options");
        if (!"nosniff".equalsIgnoreCase(nosniff)) {
            out.add(headerFinding("API-HDR-NOSNIFF", "Missing X-Content-Type-Options: nosniff", Severity.LOW, where,
                    "X-Content-Type-Options response header: " + (nosniff == null ? "missing" : nosniff),
                    "X-Content-Type-Options: nosniff", "Header missing or value was not nosniff",
                    "Send X-Content-Type-Options: nosniff", nosniff));
        }
        if (r.getHeader("Content-Security-Policy") == null && r.getHeader("X-Frame-Options") == null) {
            out.add(headerFinding("API-HDR-FRAMING", "No clickjacking protection", Severity.LOW, where,
                    "Response did not include Content-Security-Policy or X-Frame-Options",
                    "Content-Security-Policy with frame-ancestors or X-Frame-Options",
                    "Both framing-protection headers missing",
                    "Send Content-Security-Policy: frame-ancestors 'none'", null));
        }
        for (String h : List.of("Server", "X-Powered-By", "X-AspNet-Version")) {
            String v = r.getHeader(h);
            if (v != null && (h.equals("X-Powered-By") || h.equals("X-AspNet-Version") || VERSIONED_BANNER.matcher(v).matches())) {
                out.add(finding("API-BANNER-" + h.toUpperCase(Locale.ROOT), "Technology/version disclosure via " + h, Severity.LOW, where,
                        h + ": " + v, "Remove or genericise the " + h + " header"));
            }
        }
    }
}
