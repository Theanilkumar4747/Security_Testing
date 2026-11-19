package com.venTech.security.scanners.dast;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.venTech.security.utils.HttpUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.WebDriverWait;

/** Launches Chrome, records the live dashboard, and emits normalized DAST findings. */
public class SeleniumDashboardScanner extends BaseScanner {
    @Override public String name() { return "selenium-dashboard"; }
    @Override public Category category() { return Category.DAST; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        String target = cfg.target().url();
        ChromeOptions options = new ChromeOptions();
        if ("true".equalsIgnoreCase(cfg.option("headless", "false"))) {
            options.addArguments("--headless=new");
        }
        options.addArguments("--window-size=1440,1000", "--disable-gpu", "--no-sandbox");
        options.setAcceptInsecureCerts("true".equalsIgnoreCase(cfg.option("insecureTls", "false")));

        ObjectNode raw = MAPPER.createObjectNode();
        raw.put("url", target);
        raw.set("sqlLoginCases", skippedCombinedLoginCases());
        WebDriver driver = new ChromeDriver(options);
        try {
            long started = System.currentTimeMillis();
            driver.manage().timeouts().pageLoadTimeout(cfg.timeout());
            driver.get(target);
            new WebDriverWait(driver, java.time.Duration.ofSeconds(20))
                    .until(d -> ((JavascriptExecutor) d).executeScript("return document.readyState").equals("complete"));

            String title = driver.getTitle();
            String bodyText = (String) ((JavascriptExecutor) driver)
                    .executeScript("return document.body ? document.body.innerText : ''");
            raw.put("title", title);
            raw.put("currentUrl", driver.getCurrentUrl());
            raw.put("bodyText", bodyText);

            if ("true".equalsIgnoreCase(cfg.option("sqlInjectionCheck", "true"))) {
                String loginPath = cfg.option("loginPath", "/login");
                String loginUrl = URI.create(target).resolve(loginPath).toString();
                if (!URI.create(loginUrl).getHost().equalsIgnoreCase(cfg.target().host())) {
                    throw new IllegalArgumentException("loginPath must remain on the authorized target host");
                }
                driver.get(loginUrl);
                var loginForm = driver.findElements(org.openqa.selenium.By.cssSelector("form")).stream()
                        .filter(form -> !form.findElements(org.openqa.selenium.By.cssSelector("input[type='password']")).isEmpty())
                        .findFirst().orElse(null);
                if (loginForm == null) {
                    raw.put("sqlInjectionTested", false);
                    raw.put("sqlInjectionResult", "No login form with a password field found at " + loginUrl);
                    log.warn("SQL injection check not run: no login form found at {}", loginUrl);
                } else {
                    var username = loginForm.findElements(org.openqa.selenium.By.cssSelector(
                                    "input[type='email'], input[type='text'], input:not([type])"))
                            .stream().findFirst().orElse(null);
                    if (username == null) {
                        raw.put("sqlInjectionTested", false);
                        raw.put("sqlInjectionResult", "No username/email field found at " + loginUrl);
                        log.warn("SQL injection check not run: no username field found at {}", loginUrl);
                    } else {
                        var password = loginForm.findElement(org.openqa.selenium.By.cssSelector("input[type='password']"));
                        username.clear();
                        username.sendKeys("sqli-check'");
                        password.sendKeys("invalid-sqli-check-password");
                        ((JavascriptExecutor) driver).executeScript("arguments[0].requestSubmit()", loginForm);
                        Thread.sleep(1200);
                        String loginResponse = (String) ((JavascriptExecutor) driver)
                                .executeScript("return document.body ? document.body.innerText : ''");
                        String sqlError = findSqlError(loginResponse);
                        raw.put("sqlInjectionTested", true);
                        raw.put("sqlInjectionResult", sqlError == null
                                ? "No database error signature detected after a single quote probe"
                                : "Database error signature detected");
                        raw.put("sqlInjectionError", sqlError);
                        raw.put("sqlInjectionLocation", loginUrl);
                        log.info("Login SQL injection probe completed: tested={}, databaseErrorDetected={}",
                                true, sqlError != null);
                    }
                }
            } else {
                raw.put("sqlInjectionTested", false);
                raw.put("sqlInjectionResult", "Disabled by scanner configuration");
            }

            if ("true".equalsIgnoreCase(cfg.option("screenshot", "true"))) {
                Path screenshot = cfg.outputDir().resolve("veportal-dashboard.png");
                Files.createDirectories(cfg.outputDir());
                Files.write(screenshot, ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES));
                raw.put("screenshot", screenshot.toAbsolutePath().toString());
            }
            raw.put("browserLaunchMs", System.currentTimeMillis() - started);
        } finally {
            driver.quit();
        }

        HttpUtil.Response response = HttpUtil.get(target, null);
        raw.put("statusCode", response.status());
        raw.put("hsts", response.header("Strict-Transport-Security"));
        raw.put("nosniff", response.header("X-Content-Type-Options"));

        String output = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(raw);
        Path report = file(cfg, "selenium-dashboard.json");
        FileUtils.writeString(report, output);
        log.info("Browser launched for {}", target);
        log.info("Dashboard result: URL={}, currentStatus={}, HSTS={}, X-Content-Type-Options={}",
                target, response.status(), response.header("Strict-Transport-Security"),
                response.header("X-Content-Type-Options"));
        return output;
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        JsonNode root = MAPPER.readTree(raw);
        String target = root.path("url").asText();
        List<Vulnerability> findings = new ArrayList<>();
        if (!root.hasNonNull("hsts")) {
            findings.add(finding("SELENIUM-HSTS-MISSING", "Strict Transport Security header missing",
                    "The HTTPS dashboard response does not include HSTS.",
                    "Add Strict-Transport-Security with an appropriate max-age and preload policy.",
                    "Strict-Transport-Security response header: missing",
                    "Strict-Transport-Security: max-age=31536000", target));
        }
        if (!"nosniff".equalsIgnoreCase(root.path("nosniff").asText())) {
            findings.add(finding("SELENIUM-NOSNIFF-MISSING", "X-Content-Type-Options header missing",
                    "The dashboard response does not enforce MIME sniffing protection.",
                    "Set X-Content-Type-Options to nosniff on HTTPS responses.",
                    "X-Content-Type-Options response header: missing",
                    "X-Content-Type-Options: nosniff", target));
        }
        if (root.path("sqlInjectionError").isTextual()) {
            String loginUrl = root.path("sqlInjectionLocation").asText(target);
            findings.add(Vulnerability.builder().id("SELENIUM-SQLI-ERROR")
                    .title("Database error exposed by login input")
                    .description("A single-quote login input caused a database error signature to appear in the response.")
                    .severity(Severity.HIGH).scanner(name()).category(category()).location(loginUrl)
                    .evidence(root.path("sqlInjectionError").asText())
                    .expectedResult("Generic authentication error without database details")
                    .actualResult("Database error signature returned")
                    .remediation("Use parameterized queries for authentication and return generic errors without database details.")
                    .httpMethod("POST").build());
        } else if (root.path("sqlInjectionTested").asBoolean(false)) {
            String loginUrl = root.path("sqlInjectionLocation").asText(target);
            findings.add(Vulnerability.builder().id("SELENIUM-SQLI-CHECKED")
                    .title("Login SQL injection error-disclosure probe completed")
                    .description("A single-quote input and invalid password were submitted to the login form. No common database error signature was visible in the response; this does not prove the endpoint is free of SQL injection.")
                    .severity(Severity.INFO).scanner(name()).category(category()).location(loginUrl)
                    .evidence("One non-destructive single-quote input submitted; no database error signature detected")
                    .expectedResult("Generic authentication error without database details")
                    .actualResult("No database error signature detected")
                    .remediation("For stronger assurance, review server-side parameterized queries and test in a dedicated authorized environment.")
                    .httpMethod("POST").build());
        }
        if (root.path("sqlLoginCases").isArray() && !root.path("sqlLoginCases").isEmpty()) {
            String loginUrl = root.path("sqlInjectionLocation").asText(
                    URI.create(target).resolve("/login").toString());
            String caseIds = java.util.stream.StreamSupport.stream(
                            root.path("sqlLoginCases").spliterator(), false)
                    .map(item -> item.path("id").asText())
                    .filter(id -> !id.isBlank())
                    .collect(java.util.stream.Collectors.joining(", "));
            findings.add(Vulnerability.builder().id("SELENIUM-SQLI-SCOPE")
                    .title("Combined login SQL injection cases not executed")
                    .description("Cases " + caseIds + " were recorded as not run. The current live check is limited to one single-quote error-disclosure probe; it does not exercise authentication bypass, query alteration, encoded payloads, or oversized input.")
                    .severity(Severity.INFO).scanner(name()).category(category()).location(loginUrl)
                    .evidence("Not run: " + caseIds)
                    .expectedResult("Use application-owned isolated integration tests for these cases")
                    .actualResult("Not executed by this external-target scanner")
                    .remediation("Verify server-side parameterized queries and run the complete negative test matrix only against an isolated test application.")
                    .httpMethod("N/A").build());
        }
        for (Vulnerability finding : findings) {
            log.warn("Finding: {} | {} | {}", finding.id(), finding.title(), finding.location());
        }
        return findings;
    }

    private static ArrayNode skippedCombinedLoginCases() {
        ArrayNode cases = MAPPER.createArrayNode();
        addSkippedCase(cases, "SQL_LOGIN_001", "authentication-bypass payload");
        addSkippedCase(cases, "SQL_LOGIN_002", "authentication-bypass payload");
        addSkippedCase(cases, "SQL_LOGIN_003", "authentication-bypass payload");
        addSkippedCase(cases, "SQL_LOGIN_004", "query-altering comment payload");
        addSkippedCase(cases, "SQL_LOGIN_005", "UNION data-disclosure payload");
        addSkippedCase(cases, "SQL_LOGIN_006", "stacked-statement payload");
        addSkippedCase(cases, "SQL_LOGIN_007", "boolean query-altering payload");
        addSkippedCase(cases, "SQL_LOGIN_008", "authentication-bypass payload");
        addSkippedCase(cases, "SQL_LOGIN_009", "oversized input can stress the target");
        addSkippedCase(cases, "SQL_LOGIN_010", "encoded SQL injection payload");
        return cases;
    }

    private static void addSkippedCase(ArrayNode cases, String id, String reason) {
        ObjectNode item = cases.addObject();
        item.put("id", id);
        item.put("status", "NOT_RUN");
        item.put("reason", reason + " is not submitted by the external-target scanner");
    }

    static String findSqlError(String body) {
        if (body == null || body.isBlank()) return null;
        String lower = body.toLowerCase(java.util.Locale.ROOT);
        for (String signature : List.of(
                "sql syntax", "sqlstate", "syntax error", "incorrect syntax near",
                "unclosed quotation mark", "mysql_", "you have an error in your sql syntax",
                "warning: mysql", "pg_query()", "postgresql query failed", "unterminated quoted string",
                "ora-", "sqlite error", "sqlite3::exception", "microsoft sql server",
                "odbc sql server driver", "jdbc exception", "hibernate exception")) {
            int index = lower.indexOf(signature);
            if (index >= 0) {
                int start = Math.max(0, index - 40);
                int end = Math.min(body.length(), index + signature.length() + 80);
                return body.substring(start, end).replaceAll("\\s+", " ").trim();
            }
        }
        return null;
    }

    private Vulnerability finding(String id, String title, String description, String remediation,
                                  String evidence, String expected, String target) {
        return Vulnerability.builder().id(id).title(title).description(description)
                .severity(Severity.MEDIUM).scanner(name()).category(category()).location(target)
                .evidence(evidence).expectedResult(expected).actualResult("missing")
                .remediation(remediation).httpMethod("GET").build();
    }
}
