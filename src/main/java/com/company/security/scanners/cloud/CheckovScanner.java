package com.company.security.scanners.cloud;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/** Checkov IaC scanning (Terraform, CloudFormation, Kubernetes, Dockerfile, Helm...). */
public class CheckovScanner extends BaseScanner {
    @Override public String name() { return "checkov"; }
    @Override public Category category() { return Category.CLOUD; }
    @Override protected String requiredBinary() { return "checkov"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        String dir = cfg.target().iacPath() == null || cfg.target().iacPath().isBlank() ? sourcePath(cfg) : cfg.target().iacPath();
        String out = run(cfg, List.of("checkov", "-d", dir, "-o", "json", "--quiet", "--compact"), null, 0, 1).stdout();
        FileUtils.writeString(file(cfg, "checkov.json"), out);
        return out.isBlank() ? "{}" : out;
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        JsonNode root = MAPPER.readTree(raw);
        List<Vulnerability> list = new ArrayList<>();
        if (root.isArray()) root.forEach(r -> collect(r, list)); else collect(root, list);
        return list;
    }

    private void collect(JsonNode report, List<Vulnerability> out) {
        for (JsonNode c : report.path("results").path("failed_checks")) {
            JsonNode range = c.path("file_line_range");
            out.add(Vulnerability.builder()
                    .id(text(c, "check_id", "checkov"))
                    .title(text(c, "check_name", "IaC misconfiguration"))
                    .description("Resource: " + text(c, "resource", "?"))
                    .severity(c.path("severity").isNull() || c.path("severity").isMissingNode()
                            ? Severity.MEDIUM : Severity.fromString(text(c, "severity", "MEDIUM")))
                    .scanner(name()).category(category())
                    .location(text(c, "file_path", "?") + ":" + range.path(0).asInt(0))
                    .remediation(text(c, "guideline", null))
                    .build());
        }
    }
}
