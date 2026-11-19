package com.venTech.security.scanners.dast;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.DockerRunner;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * OWASP ZAP via the official container. Modes: baseline (passive, default), full (active - attacks
 * the target, only use on systems you own) and api (OpenAPI/SOAP/GraphQL definition scan).
 */
public class ZAPScanner extends BaseScanner {
    @Override public String name() { return "zap"; }
    @Override public Category category() { return Category.DAST; }
    @Override public boolean isAvailable() { return DockerRunner.isAvailable(); }
    @Override protected String requiredBinary() { return "docker"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        String mode = cfg.option("mode", "baseline");
        String image = cfg.option("image", "ghcr.io/zaproxy/zaproxy:stable");
        String target = cfg.target().url();

        // /zap/wrk is writable by the container's non-root user
        cfg.outputDir().toFile().setWritable(true, false);
        FileUtils.extractResource("rules/zap-rules.tsv", cfg.outputDir());

        List<String> args = new ArrayList<>();
        switch (mode) {
            case "full" -> args.addAll(List.of("zap-full-scan.py", "-t", target, "-m", cfg.option("spiderMinutes", "5")));
            case "api" -> {
                String spec = cfg.target().openApiSpec() != null ? cfg.target().openApiSpec() : target;
                args.addAll(List.of("zap-api-scan.py", "-t", spec, "-f", cfg.option("format", "openapi")));
            }
            default -> args.addAll(List.of("zap-baseline.py", "-t", target, "-m", cfg.option("spiderMinutes", "3")));
        }
        args.addAll(List.of("-J", "zap-report.json", "-c", "zap-rules.tsv", "-I"));

        List<String> dockerOpts = new ArrayList<>();
        String network = cfg.option("network", "");
        if (!network.isBlank()) { dockerOpts.add("--network"); dockerOpts.add(network); }

        var r = DockerRunner.run(image, args, Map.of("/zap/wrk", cfg.outputDir()), null, dockerOpts, cfg.timeout());
        if (r.exitCode() > 2) throw new java.io.IOException("ZAP failed (" + r.exitCode() + "): " + truncate(r.stderr() + r.stdout(), 800));
        Path report = file(cfg, "zap-report.json");
        return FileUtils.readString(report);
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        JsonNode sites = MAPPER.readTree(raw).path("site");
        List<JsonNode> siteList = new ArrayList<>();
        if (sites.isArray()) sites.forEach(siteList::add); else if (!sites.isMissingNode()) siteList.add(sites);

        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode site : siteList) {
            for (JsonNode a : site.path("alerts")) {
                Severity sev = switch (text(a, "riskcode", "0")) {
                    case "3" -> Severity.HIGH;
                    case "2" -> Severity.MEDIUM;
                    case "1" -> Severity.LOW;
                    default -> Severity.INFO;
                };
                String cwe = text(a, "cweid", "0");
                list.add(Vulnerability.builder()
                        .id("ZAP-" + text(a, "pluginid", "0"))
                        .title(text(a, "alert", text(a, "name", "ZAP alert")))
                        .description(stripHtml(text(a, "desc", null)))
                        .severity(sev).scanner(name()).category(category())
                        .location(a.path("instances").path(0).path("uri").asText(text(site, "@name", "?")))
                        .cwe(cwe.equals("0") || cwe.equals("-1") ? null : "CWE-" + cwe)
                        .remediation(stripHtml(text(a, "solution", null)))
                        .build());
            }
        }
        return list;
    }
}
