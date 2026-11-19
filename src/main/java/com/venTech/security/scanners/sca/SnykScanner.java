package com.venTech.security.scanners.sca;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.CommandExecutor;
import com.venTech.security.utils.EnvConfig;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Snyk Open Source. Requires SNYK_TOKEN. */
public class SnykScanner extends BaseScanner {
    @Override public String name() { return "snyk"; }
    @Override public Category category() { return Category.SCA; }
    @Override protected String requiredBinary() { return "snyk"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Map<String, String> env = new HashMap<>();
        env.put("SNYK_TOKEN", EnvConfig.require("snyk.token"));
        List<String> cmd = List.of("snyk", "test", "--json", "--all-projects", "--severity-threshold=low");
        // snyk exits 1 when vulnerabilities are found, 2 on failure
        var r = CommandExecutor.run(cmd, java.nio.file.Path.of(sourcePath(cfg)), cfg.timeout(), env);
        if (r.exitCode() > 1) throw new java.io.IOException("snyk failed (" + r.exitCode() + "): " + truncate(r.stdout() + r.stderr(), 600));
        FileUtils.writeString(file(cfg, "snyk.json"), r.stdout());
        return r.stdout();
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        JsonNode root = MAPPER.readTree(raw);
        List<Vulnerability> list = new ArrayList<>();
        if (root.isArray()) root.forEach(p -> collect(p, list)); else collect(root, list);
        return list;
    }

    private void collect(JsonNode project, List<Vulnerability> out) {
        for (JsonNode v : project.path("vulnerabilities")) {
            JsonNode ids = v.path("identifiers");
            out.add(Vulnerability.builder()
                    .id(text(v, "id", "snyk"))
                    .title(text(v, "title", "Snyk vulnerability"))
                    .description(text(v, "description", null))
                    .severity(Severity.fromString(text(v, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(text(v, "packageName", "?") + "@" + text(v, "version", "?"))
                    .cve(ids.path("CVE").path(0).asText(null))
                    .cwe(ids.path("CWE").path(0).asText(null))
                    .remediation(v.path("fixedIn").isArray() && v.path("fixedIn").size() > 0
                            ? "Upgrade to " + v.path("fixedIn").get(0).asText() : null)
                    .build());
        }
    }
}
