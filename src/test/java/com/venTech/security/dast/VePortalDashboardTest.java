package com.venTech.security.dast;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.venTech.security.model.Vulnerability;
import com.venTech.security.scanners.dast.SeleniumDashboardScanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.response.Response;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.WebDriverWait;

class VePortalDashboardTest {
    private static final String DEFAULT_URL = "https://pp-dev.veportal.in/client/dashboard";
    private WebDriver driver;

    @BeforeEach
    void startBrowser() {
        String url = System.getProperty("dashboard.test.url",
                System.getenv().getOrDefault("DASHBOARD_TEST_URL", DEFAULT_URL));
        Assumptions.assumeTrue(url.startsWith("https://"),
                "Dashboard browser tests require an HTTPS URL");
        ChromeOptions options = new ChromeOptions();
        if ("true".equalsIgnoreCase(System.getProperty("dashboard.test.headless",
                System.getenv().getOrDefault("DASHBOARD_TEST_HEADLESS", "false")))) {
            options.addArguments("--headless=new");
        }
        options.addArguments("--window-size=1440,1000", "--disable-gpu", "--no-sandbox");
        if ("true".equalsIgnoreCase(System.getenv().getOrDefault("DASHBOARD_TEST_INSECURE_TLS", "false"))) {
            options.setAcceptInsecureCerts(true);
        }
        driver = new ChromeDriver(options);
        driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(30));
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(2));
    }

    @AfterEach
    void stopBrowser() {
        if (driver != null) {
            driver.quit();
        }
    }

    @Test
    void dashboardShellLoadsAndPrimaryNavigationIsPresent() throws Exception {
        driver.get(testUrl());
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(20));
        wait.until(d -> ((JavascriptExecutor) d).executeScript("return document.readyState").equals("complete"));
        String bodyText = (String) ((JavascriptExecutor) driver)
                .executeScript("return document.body ? document.body.innerText : ''");
        assertThat(bodyText).containsAnyOf("Pravesh Prahari", "Dashboard", "Loading dashboard");
        assertThat(driver.getCurrentUrl()).startsWith(origin(testUrl()));
        if ("true".equalsIgnoreCase(System.getProperty("dashboard.test.capture", "false"))) {
            Path screenshot = Path.of("target", "security-reports", "veportal-dashboard.png");
            Files.createDirectories(screenshot.getParent());
            Files.write(screenshot, ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES));
        }
    }

    @Test
    void dashboardNavigationKeepsTrafficOnTheApprovedHost() {
        driver.get(testUrl());
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(20));
        driver.get(testUrl().replace("/client/dashboard", "/client/center"));
        wait.until(d -> ((JavascriptExecutor) d).executeScript("return document.readyState").equals("complete"));
        assertThat(driver.getCurrentUrl()).startsWith(origin(testUrl()));
    }

    @Test
    void dashboardHeaderFindingsMatchTheLiveResponse() throws Exception {
        Response response = given()
                .relaxedHTTPSValidation()
                .redirects().follow(true)
                .when()
                .get(testUrl())
                .then()
                .extract().response();
        assertThat(response.statusCode()).isBetween(200, 399);
        assertThat(testUrl()).startsWith("https://");
        var observed = new ObjectMapper().createObjectNode();
        observed.put("url", testUrl());
        observed.put("statusCode", response.statusCode());
        putHeader(observed, "hsts", response.getHeader("Strict-Transport-Security"));
        putHeader(observed, "nosniff", response.getHeader("X-Content-Type-Options"));
        List<String> findingIds = new SeleniumDashboardScanner()
                .parse(observed.toString()).stream().map(Vulnerability::id).toList();
        assertThat(findingIds.contains("SELENIUM-HSTS-MISSING"))
                .isEqualTo(response.getHeader("Strict-Transport-Security") == null);
        assertThat(findingIds.contains("SELENIUM-NOSNIFF-MISSING"))
                .isEqualTo(!"nosniff".equalsIgnoreCase(response.getHeader("X-Content-Type-Options")));
    }

    private static void putHeader(com.fasterxml.jackson.databind.node.ObjectNode node, String name, String value) {
        if (value == null) {
            node.putNull(name);
        } else {
            node.put(name, value);
        }
    }

    private String testUrl() {
        return System.getProperty("dashboard.test.url",
                System.getenv().getOrDefault("DASHBOARD_TEST_URL", DEFAULT_URL));
    }

    private static String origin(String url) {
        URI uri = URI.create(url);
        return uri.getScheme() + "://" + uri.getRawAuthority();
    }
}
