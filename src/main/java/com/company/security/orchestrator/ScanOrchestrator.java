package com.company.security.orchestrator;

import com.company.security.core.ScanConfig;
import com.company.security.core.ScanResult;
import com.company.security.core.ScannerInterface;
import com.company.security.core.ScannerInterface.Category;
import com.company.security.core.Severity;
import com.company.security.gate.BuildBreaker;
import com.company.security.gate.QualityGate;
import com.company.security.integrations.DefectDojoClient;
import com.company.security.integrations.EmailNotifier;
import com.company.security.integrations.JiraClient;
import com.company.security.integrations.SlackNotifier;
import com.company.security.model.ScanReport;
import com.company.security.model.Target;
import com.company.security.orchestrator.ParallelScanExecutor.ScanTask;
import com.company.security.reporting.DashboardPublisher;
import com.company.security.reporting.ReportGenerator;
import com.company.security.scanners.api.OwaspApiTop10Checks;
import com.company.security.scanners.api.RestAssuredSecurityTests;
import com.company.security.scanners.api.SchemathesisRunner;
import com.company.security.scanners.cloud.CheckovScanner;
import com.company.security.scanners.cloud.KubeBenchScanner;
import com.company.security.scanners.cloud.ProwlerScanner;
import com.company.security.scanners.dast.BurpScanner;
import com.company.security.scanners.dast.NucleiScanner;
import com.company.security.scanners.dast.ZAPScanner;
import com.company.security.scanners.sast.CheckmarxScanner;
import com.company.security.scanners.sast.SemgrepScanner;
import com.company.security.scanners.sast.SonarQubeScanner;
import com.company.security.scanners.sca.OWASPDependencyCheckScanner;
import com.company.security.scanners.sca.SnykScanner;
import com.company.security.scanners.sca.TrivyScanner;
import com.company.security.scanners.secrets.GitleaksScanner;
import com.company.security.scanners.secrets.TruffleHogScanner;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import com.company.security.utils.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Entry point. Selects scanners (scanners-config.yaml + CLI filters), runs them in parallel,
 * writes reports, publishes/notifies, evaluates the quality gate and returns the process exit code.
 *
 * <pre>
 * java -jar security-framework.jar --categories=SAST,SCA,SECRETS --source=.
 * java -jar security-framework.jar --scanners=zap,nuclei --url=https://staging.example.com
 * Flags: --name --url --source --image --spec --iac --out --config --gate-config --formats
 *        --scanners --categories --no-gate --no-publish --schedule-hours=N
 * Exit codes: 0 gate passed, 1 gate failed, 2 configuration/runtime error
 * </pre>
 */
public class ScanOrchestrator {
    private static final Logger LOG = Logger.get(ScanOrchestrator.class);

    private static final Map<String, Supplier<ScannerInterface>> REGISTRY = new LinkedHashMap<>();
    static {
        REGISTRY.put("sonarqube", SonarQubeScanner::new);
        REGISTRY.put("semgrep", SemgrepScanner::new);
        REGISTRY.put("checkmarx", CheckmarxScanner::new);
        REGISTRY.put("owasp-dependency-check", OWASPDependencyCheckScanner::new);
        REGISTRY.put("snyk", SnykScanner::new);
        REGISTRY.put("trivy", TrivyScanner::new);
        REGISTRY.put("zap", ZAPScanner::new);
        REGISTRY.put("burp", BurpScanner::new);
        REGISTRY.put("nuclei", NucleiScanner::new);
        REGISTRY.put("restassured-security-tests", RestAssuredSecurityTests::new);
        REGISTRY.put("schemathesis", SchemathesisRunner::new);
        REGISTRY.put("owasp-api-top10", OwaspApiTop10Checks::new);
        REGISTRY.put("gitleaks", GitleaksScanner::new);
        REGISTRY.put("trufflehog", TruffleHogScanner::new);
        REGISTRY.put("checkov", CheckovScanner::new);
        REGISTRY.put("kube-bench", KubeBenchScanner::new);
        REGISTRY.put("prowler", ProwlerScanner::new);
    }

    public static void main(String[] argv) throws Exception {
        Map<String, String> args = parseArgs(argv);
        ScanOrchestrator orchestrator = new ScanOrchestrator();
        if (args.containsKey("schedule-hours")) {
            try (ScanScheduler scheduler = new ScanScheduler()) {
                scheduler.scheduleEvery(Duration.ofHours(Long.parseLong(args.get("schedule-hours"))), () -> {
                    try { orchestrator.execute(args); } catch (Exception e) { LOG.error("Scheduled run failed", e); }
                });
                Thread.currentThread().join();
            }
            return;
        }
        int code;
        try {
            code = orchestrator.execute(args);
        } catch (Exception e) {
            LOG.error("Scan run failed", e);
            code = 2;
        }
        System.exit(code);
    }

    /** Runs the full pipeline once and returns the exit code. */
    public int execute(Map<String, String> args) throws Exception {
        String source = arg(args, "source", "scan.source", ".");
        Target target = new Target(arg(args, "name", "scan.name", "application"), arg(args, "url", "scan.url", null),
                source, arg(args, "image", "scan.image", null), arg(args, "spec", "scan.openapi", null),
                arg(args, "iac", "scan.iac", source));
        Path outDir = Path.of(arg(args, "out", "scan.output", "target/security-reports"));
        Files.createDirectories(outDir);
        LOG.info("Starting security scan for target '{}' (host: {})", target.name(),
                target.host() == null ? "local/source-only" : target.host());
        LOG.info("Reports and raw scanner output will be written to {}", outDir.toAbsolutePath());

        ScanReport report = runScans(target, outDir, args);

        LOG.info("Evaluating quality gate for scan run {}", report.id());
        QualityGate.GateResult gate = args.containsKey("no-gate")
                ? new QualityGate.GateResult(true, List.of(), report.countBySeverity(), 0)
                : (args.containsKey("gate-config")
                    ? QualityGate.fromYaml(FileUtils.readString(Path.of(args.get("gate-config")))) : QualityGate.load()).evaluate(report);
        LOG.info("Quality gate evaluation complete: {} ({} violation(s))",
                gate.passed() ? "PASSED" : "FAILED", gate.violations().size());

        List<String> formats = new ArrayList<>(csv(arg(args, "formats", "report.formats", "html,json,sarif")));
        Map<String, Path> artifacts = new ReportGenerator().generate(report, outDir, formats, gate);
        LOG.info("Generated report artifacts: {}", artifacts.values());

        FileUtils.writeString(outDir.resolve("gate-result.json"),
                new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(gate));
        LOG.info("Wrote quality gate result to {}", outDir.resolve("gate-result.json").toAbsolutePath());

        if (!args.containsKey("no-publish")) {
            LOG.info("Starting configured report publishing and notifications");
            publishAndNotify(report, gate, artifacts);
        } else {
            LOG.info("Report publishing and notifications disabled by --no-publish");
        }
        int code = BuildBreaker.exitCode(gate);
        BuildBreaker.log(gate);
        LOG.info("Scan run {} completed with exit code {}", report.id(), code);
        return code;
    }

    public ScanReport runScans(Target target, Path outDir, Map<String, String> args) throws Exception {
        JsonNode cfgRoot = loadScannerConfig(args.get("config")).path("scanners");
        Set<String> nameFilter = csv(args.get("scanners"));
        Set<String> catFilter = csv(args.get("categories")).stream().map(s -> s.toUpperCase(Locale.ROOT)).collect(Collectors.toSet());

        List<ScanTask> tasks = new ArrayList<>();
        for (var entry : REGISTRY.entrySet()) {
            String name = entry.getKey();
            JsonNode node = cfgRoot.path(name);
            boolean enabled = nameFilter.isEmpty() ? node.path("enabled").asBoolean(false) : nameFilter.contains(name);
            if (!enabled) continue;
            ScannerInterface scanner = entry.getValue().get();
            if (!catFilter.isEmpty() && !catFilter.contains(scanner.category().name())) continue;

            Map<String, String> options = new HashMap<>();
            node.path("options").fields().forEachRemaining(e -> options.put(e.getKey(), e.getValue().asText()));
            Duration timeout = Duration.ofMinutes(node.path("timeoutMinutes").asInt(15));
            tasks.add(new ScanTask(scanner, new ScanConfig(target, outDir.resolve("raw").resolve(name), timeout, options)));
        }
        if (tasks.isEmpty()) throw new IllegalStateException("No scanners selected - check --scanners/--categories and scanners-config.yaml");
        LOG.info("Selected {} scanner(s): {}", tasks.size(), tasks.stream().map(t -> t.scanner().name()).toList());

        Instant start = Instant.now();
        List<ScanResult> results;
        try (ParallelScanExecutor executor = new ParallelScanExecutor(EnvConfig.getInt("scan.parallelism", 4))) {
            results = executor.executeAll(tasks);
        }
        LOG.info("All selected scanners finished: {} succeeded, {} failed, {} skipped",
                results.stream().filter(r -> r.status() == ScanResult.Status.SUCCESS).count(),
                results.stream().filter(r -> r.status() == ScanResult.Status.FAILED).count(),
                results.stream().filter(r -> r.status() == ScanResult.Status.SKIPPED).count());
        return new ScanReport(UUID.randomUUID().toString().substring(0, 8), start, Instant.now(), target, results);
    }

    private void publishAndNotify(ScanReport report, QualityGate.GateResult gate, Map<String, Path> artifacts) {
        LOG.info("Publishing scan run {} to configured integrations", report.id());
        attempt("dashboard", () -> new DashboardPublisher().publish(report, artifacts));
        if (EnvConfig.getBool("integration.defectdojo.enabled", false) && artifacts.containsKey("sarif")) {
            attempt("defectdojo", () -> DefectDojoClient.fromEnv().importScan(artifacts.get("sarif"), report.target().name()));
        }
        if (EnvConfig.getBool("integration.jira.enabled", false)) {
            attempt("jira", () -> JiraClient.fromEnv().createIssues(report.vulnerabilities(),
                    Severity.valueOf(EnvConfig.get("integration.jira.minSeverity", "HIGH")), EnvConfig.getInt("integration.jira.maxIssues", 25)));
        }
        boolean notifyOnlyOnFail = EnvConfig.getBool("notify.onlyOnFailure", true);
        if (!gate.passed() || !notifyOnlyOnFail) {
            if (EnvConfig.getBool("integration.slack.enabled", false)) {
                attempt("slack", () -> SlackNotifier.fromEnv().notifyScan(report, gate));
            }
            if (EnvConfig.getBool("integration.email.enabled", false)) {
                attempt("email", () -> EmailNotifier.fromEnv().notifyScan(report, gate, artifacts.get("html")));
            }
        }
    }

    @FunctionalInterface private interface ThrowingRunnable { void run() throws Exception; }

    private static void attempt(String what, ThrowingRunnable r) {
        try { r.run(); LOG.info("{} integration completed", what); }
        catch (Exception e) { LOG.error("Integration '" + what + "' failed (scan result unaffected)", e); }
    }

    private static JsonNode loadScannerConfig(String path) throws Exception {
        String yaml = path != null ? FileUtils.readString(Path.of(path)) : FileUtils.readResource("config/scanners-config.yaml");
        return new YAMLMapper().readTree(yaml);
    }

    private static String arg(Map<String, String> args, String key, String prop, String def) {
        return args.containsKey(key) ? args.get(key) : EnvConfig.get(prop, def);
    }

    private static Set<String> csv(String v) {
        if (v == null || v.isBlank()) return Set.of();
        return Arrays.stream(v.split("[,;\\s]+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    static Map<String, String> parseArgs(String[] argv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < argv.length; i++) {
            String a = argv[i];
            if (!a.startsWith("--")) continue;
            String key = a.substring(2);
            String value;
            int eq = key.indexOf('=');
            if (eq >= 0) {
                value = key.substring(eq + 1);
                key = key.substring(0, eq);
            } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
                value = argv[++i];
            } else {
                value = "true";
            }
            m.put(key, value);
        }
        return m;
    }
}
