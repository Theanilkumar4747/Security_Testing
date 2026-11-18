package com.company.security.scanners.api;

import static com.company.security.scanners.api.RestAssuredSecurityTests.finding;
import static com.company.security.scanners.api.RestAssuredSecurityTests.spec;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.EnvConfig;
import com.fasterxml.jackson.databind.JsonNode;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Automated checks mapped to the OWASP API Security Top 10 (2023): API1 BOLA, API2 broken authentication,
 * API3 property-level exposure, API4 resource consumption, API5 BFLA, API8 misconfiguration, API9 inventory.
 * Tokens come from the environment (api.token.a = normal user A, api.token.b = user B). Probes are read-only.
 */
public class OwaspApiTop10Checks extends BaseScanner {

    private static final List<String> SENSITIVE_FIELDS = List.of("password", "passwd", "secret", "ssn",
            "creditcard", "card_number", "api_key", "apikey", "private_key", "access_token", "refresh_token", "passwordhash");
    private static final List<String> RISKY_INVENTORY = List.of("/actuator/env", "/actuator/heapdump", "/.env", "/debug", "/.git/config");
    private static final List<String> DOC_INVENTORY = List.of("/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
            "/swagger-ui/index.html", "/actuator", "/api/v0/", "/api/v1/");

    @Override public String name() { return "owasp-api-top10"; }
    @Override public Category category() { return Category.API; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception { return toRaw(runChecks(cfg)); }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception { return fromRaw(raw); }

    private List<Vulnerability> runChecks(ScanConfig cfg) {
        List<Vulnerability> out = new ArrayList<>();
        String base = cfg.target().url();
        String tokenA = EnvConfig.get("api.token.a", "");
        String tokenB = EnvConfig.get("api.token.b", "");
        List<String> protectedPaths = cfg.listOption("protectedPaths", "");

        api1Bola(cfg, base, tokenB, out);
        api2BrokenAuth(cfg, base, protectedPaths, out);
        api3ExcessiveExposure(cfg, base, protectedPaths, tokenA, out);
        api4RateLimit(cfg, base, out);
        api5Bfla(cfg, base, tokenA, out);
        out.addAll(new RestAssuredSecurityTests().runChecks(cfg)); // API8: security misconfiguration
        api9Inventory(cfg, base, out);
        return out;
    }

    /** API1: user B must not read user A's object. */
    private void api1Bola(ScanConfig cfg, String base, String tokenB, List<Vulnerability> out) {
        String tpl = cfg.option("bolaPathTemplate", "");
        String idA = cfg.option("idOwnedByA", "");
        if (tpl.isBlank() || idA.isBlank() || tokenB.isBlank()) return;
        String path = tpl.replace("{id}", idA);
        int sc = spec(cfg, tokenB).get(path).statusCode();
        if (sc >= 200 && sc < 300) {
            out.add(finding("API1:2023-BOLA", "Broken object level authorization", Severity.CRITICAL, base + path,
                    "User B received HTTP " + sc + " for an object owned by user A",
                    "Check object ownership on every request using the authenticated principal, not client-supplied ids"));
        }
    }

    /** API2: no token, garbage token and an unsigned (alg=none) JWT must all be rejected. */
    private void api2BrokenAuth(ScanConfig cfg, String base, List<String> paths, List<Vulnerability> out) {
        String unsigned = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + b64("{\"sub\":\"1\",\"role\":\"admin\"}") + ".";
        for (String path : paths) {
            if (ok(spec(cfg, null).get(path).statusCode())) {
                out.add(finding("API2:2023-NO-AUTH", "Endpoint reachable without authentication", Severity.HIGH, base + path,
                        "Request without credentials succeeded", "Require authentication for all non-public endpoints"));
            }
            if (ok(spec(cfg, "invalid.token.value").get(path).statusCode())) {
                out.add(finding("API2:2023-INVALID-TOKEN", "Invalid token accepted", Severity.HIGH, base + path,
                        "A malformed bearer token was accepted", "Validate token signature, issuer, audience and expiry"));
            }
            if (ok(spec(cfg, unsigned).get(path).statusCode())) {
                out.add(finding("API2:2023-JWT-ALG-NONE", "Unsigned JWT (alg=none) accepted", Severity.CRITICAL, base + path,
                        "The server accepted a JWT with no signature", "Reject alg=none and pin the expected algorithm"));
            }
        }
    }

    /** API3: responses should not carry sensitive property names. */
    private void api3ExcessiveExposure(ScanConfig cfg, String base, List<String> paths, String token, List<Vulnerability> out) {
        for (String path : paths) {
            Response r = spec(cfg, token).get(path);
            if (!ok(r.statusCode())) continue;
            try {
                List<String> hits = new ArrayList<>();
                collectSensitive(MAPPER.readTree(r.getBody().asString()), hits);
                if (!hits.isEmpty()) {
                    out.add(finding("API3:2023-EXCESSIVE-DATA", "Sensitive properties exposed in response", Severity.MEDIUM,
                            base + path, "Response contains fields: " + String.join(", ", hits),
                            "Return explicit response DTOs; never serialise internal entities"));
                }
            } catch (Exception ignored) { /* not JSON */ }
        }
    }

    /** API4: a modest burst (default 30, max 200) should trigger throttling. */
    private void api4RateLimit(ScanConfig cfg, String base, List<Vulnerability> out) {
        String path = cfg.option("rateLimitPath", "");
        if (path.isBlank()) return;
        int burst = Math.min(Math.max(cfg.intOption("burst", 30), 1), 200);
        boolean limited = false;
        for (int i = 0; i < burst && !limited; i++) {
            Response r = spec(cfg, null).get(path);
            limited = r.statusCode() == 429 || r.getHeader("Retry-After") != null || r.getHeader("X-RateLimit-Limit") != null
                    || r.getHeader("RateLimit-Limit") != null;
        }
        if (!limited) {
            out.add(finding("API4:2023-NO-RATE-LIMIT", "No rate limiting observed", Severity.MEDIUM, base + path,
                    burst + " rapid requests produced no 429 or rate-limit headers",
                    "Apply per-client rate limits and quotas at the gateway"));
        }
    }

    /** API5: a normal user must not reach admin routes. */
    private void api5Bfla(ScanConfig cfg, String base, String tokenA, List<Vulnerability> out) {
        if (tokenA.isBlank()) return;
        for (String path : cfg.listOption("adminPaths", "")) {
            int sc = spec(cfg, tokenA).get(path).statusCode();
            if (ok(sc)) {
                out.add(finding("API5:2023-BFLA", "Privileged function reachable by a normal user", Severity.HIGH, base + path,
                        "Non-admin token received HTTP " + sc, "Enforce role checks server-side on every privileged route"));
            }
        }
    }

    /** API9: exposed docs / debug endpoints. Skipped when the server answers 200 for random paths. */
    private void api9Inventory(ScanConfig cfg, String base, List<Vulnerability> out) {
        if (spec(cfg, null).get("/" + UUID.randomUUID()).statusCode() == 200) return; // catch-all server
        for (String p : RISKY_INVENTORY) {
            if (spec(cfg, null).get(p).statusCode() == 200) {
                out.add(finding("API9:2023-DEBUG-EXPOSED", "Sensitive debug/config endpoint exposed", Severity.HIGH, base + p,
                        "GET " + p + " returned 200", "Remove from production or restrict to internal networks"));
            }
        }
        for (String p : DOC_INVENTORY) {
            if (spec(cfg, null).get(p).statusCode() == 200) {
                out.add(finding("API9:2023-INVENTORY", "API documentation / legacy version exposed", Severity.LOW, base + p,
                        "GET " + p + " returned 200", "Restrict documentation to authenticated users; retire unused API versions"));
            }
        }
    }

    private static boolean ok(int sc) { return sc >= 200 && sc < 300; }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static void collectSensitive(JsonNode n, List<String> hits) {
        if (n.isObject()) {
            n.fields().forEachRemaining(e -> {
                if (SENSITIVE_FIELDS.contains(e.getKey().toLowerCase(Locale.ROOT)) && !hits.contains(e.getKey())) hits.add(e.getKey());
                collectSensitive(e.getValue(), hits);
            });
        } else if (n.isArray()) {
            n.forEach(c -> collectSensitive(c, hits));
        }
    }
}
