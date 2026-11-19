package com.venTech.security.scanners.sast;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SemgrepScanner extends BaseScanner {
    @Override public String name() { return "semgrep"; }
    @Override public Category category() { return Category.SAST; }
    @Override protected String requiredBinary() { return "semgrep"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Path out = file(cfg, "semgrep.json");
        String rules = resolveResource(cfg, cfg.option("config", "auto"));
        List<String> cmd = new ArrayList<>(List.of("semgrep", "scan", "--config", rules,
                "--json", "--output", out.toString(), "--quiet", "--metrics=off"));
        cmd.add(sourcePath(cfg));
        run(cfg, cmd, null, 0, 1);
        return FileUtils.readString(out);
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode r : MAPPER.readTree(raw).path("results")) {
            JsonNode extra = r.path("extra");
            JsonNode cwe = extra.path("metadata").path("cwe");
            String cweText = cwe.isArray() ? text(cwe, "0", null) : (cwe.isMissingNode() ? null : cwe.asText(null));
            if (cwe.isArray() && cwe.size() > 0) cweText = cwe.get(0).asText();
            list.add(Vulnerability.builder()
                    .id(text(r, "check_id", "semgrep-rule"))
                    .title(text(r, "check_id", "Semgrep finding"))
                    .description(text(extra, "message", null))
                    .severity(Severity.fromString(text(extra, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(text(r, "path", "?") + ":" + r.path("start").path("line").asInt(0))
                    .cwe(cweText)
                    .remediation(text(extra, "fix", null))
                    .build());
        }
        return list;
    }
}
