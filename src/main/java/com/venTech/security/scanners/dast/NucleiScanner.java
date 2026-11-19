package com.venTech.security.scanners.dast;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Nuclei template scanner. Defaults to medium+ severities and excludes DoS/intrusive tags. */
public class NucleiScanner extends BaseScanner {
    @Override public String name() { return "nuclei"; }
    @Override public Category category() { return Category.DAST; }
    @Override protected String requiredBinary() { return "nuclei"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Path out = file(cfg, "nuclei.jsonl");
        List<String> cmd = new ArrayList<>(List.of("nuclei", "-u", cfg.target().url(),
                "-jsonl", "-o", out.toString(), "-silent", "-disable-update-check",
                "-severity", cfg.option("severity", "medium,high,critical"),
                "-etags", cfg.option("excludeTags", "dos,intrusive,fuzz"),
                "-rate-limit", cfg.option("rateLimit", "50")));
        String templates = cfg.option("templates", "");
        if (!templates.isBlank()) { cmd.add("-t"); cmd.add(templates); }
        run(cfg, cmd, null, 0);
        return java.nio.file.Files.exists(out) ? FileUtils.readString(out) : "";
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (String line : raw.split("\\R")) {
            if (!line.startsWith("{")) continue;
            JsonNode f = MAPPER.readTree(line);
            JsonNode info = f.path("info");
            JsonNode cls = info.path("classification");
            list.add(Vulnerability.builder()
                    .id("nuclei-" + text(f, "template-id", "template"))
                    .title(text(info, "name", "Nuclei finding"))
                    .description(text(info, "description", null))
                    .severity(Severity.fromString(text(info, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(text(f, "matched-at", text(f, "host", "?")))
                    .cve(cls.path("cve-id").path(0).asText(null))
                    .cwe(cls.path("cwe-id").path(0).asText(null))
                    .remediation(text(info, "remediation", null))
                    .build());
        }
        return list;
    }
}
