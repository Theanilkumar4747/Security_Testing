package com.company.security.scanners.cloud;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/** Prowler (v4+) cloud posture scan using OCSF JSON output. Cloud credentials come from the environment. */
public class ProwlerScanner extends BaseScanner {
    @Override public String name() { return "prowler"; }
    @Override public Category category() { return Category.CLOUD; }
    @Override protected String requiredBinary() { return "prowler"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        List<String> cmd = new ArrayList<>(List.of("prowler", cfg.option("provider", "aws"),
                "-M", "json-ocsf", "-o", cfg.outputDir().toString(), "--output-filename", "prowler",
                "--status", "FAIL", "--no-banner"));
        run(cfg, cmd, null, 0, 3); // prowler exits 3 when failed checks exist
        java.nio.file.Path out = file(cfg, "prowler.ocsf.json");
        return java.nio.file.Files.exists(out) ? FileUtils.readString(out) : "[]";
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode f : MAPPER.readTree(raw)) {
            if (!"FAIL".equalsIgnoreCase(text(f, "status_code", "FAIL"))) continue;
            JsonNode info = f.path("finding_info");
            list.add(Vulnerability.builder()
                    .id(text(info, "uid", "prowler"))
                    .title(text(info, "title", text(f, "message", "Cloud misconfiguration")))
                    .description(text(f, "status_detail", text(f, "message", null)))
                    .severity(Severity.fromString(text(f, "severity", "MEDIUM")))
                    .scanner(name()).category(category())
                    .location(f.path("resources").path(0).path("uid").asText("?"))
                    .remediation(text(f.path("remediation"), "desc", null))
                    .build());
        }
        return list;
    }
}
