package com.company.security.scanners.sast;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Checkmarx One via the `cx` CLI. Credentials come from CX_CLIENT_ID / CX_CLIENT_SECRET / CX_BASE_URI. */
public class CheckmarxScanner extends BaseScanner {
    @Override public String name() { return "checkmarx"; }
    @Override public Category category() { return Category.SAST; }
    @Override protected String requiredBinary() { return "cx"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Map<String, String> env = Map.of(
                "CX_CLIENT_ID", EnvConfig.require("cx.client.id"),
                "CX_CLIENT_SECRET", EnvConfig.require("cx.client.secret"),
                "CX_BASE_URI", EnvConfig.require("cx.base.uri"));
        List<String> cmd = List.of("cx", "scan", "create",
                "--project-name", cfg.option("projectName", cfg.target().name()),
                "-s", sourcePath(cfg),
                "--branch", cfg.option("branch", "main"),
                "--scan-types", "sast",
                "--report-format", "json",
                "--output-name", "checkmarx-results",
                "--output-path", cfg.outputDir().toString());
        run(cfg, cmd, env, 0, 1);
        return FileUtils.readString(file(cfg, "checkmarx-results.json"));
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode r : MAPPER.readTree(raw).path("results")) {
            if ("NOT_EXPLOITABLE".equalsIgnoreCase(text(r, "state", ""))) continue;
            JsonNode data = r.path("data");
            JsonNode node0 = data.path("nodes").path(0);
            String cwe = text(r.path("vulnerabilityDetails"), "cweId", null);
            list.add(Vulnerability.builder()
                    .id(text(r, "similarityId", text(r, "id", "cx-result")))
                    .title(text(data, "queryName", text(r, "description", "Checkmarx finding")))
                    .description(text(r, "description", null))
                    .severity(Severity.fromString(text(r, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(text(node0, "fileName", "?") + ":" + node0.path("line").asInt(0))
                    .cwe(cwe == null ? null : "CWE-" + cwe)
                    .build());
        }
        return list;
    }
}
