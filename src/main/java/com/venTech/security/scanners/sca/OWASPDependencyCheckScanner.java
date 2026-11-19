package com.venTech.security.scanners.sca;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.EnvConfig;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

public class OWASPDependencyCheckScanner extends BaseScanner {
    @Override public String name() { return "owasp-dependency-check"; }
    @Override public Category category() { return Category.SCA; }
    @Override protected String requiredBinary() { return "dependency-check.sh"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        List<String> cmd = new ArrayList<>(List.of("dependency-check.sh",
                "--scan", sourcePath(cfg), "--format", "JSON", "--out", cfg.outputDir().toString(),
                "--project", cfg.target().name()));
        if (cfg.option("noUpdate", "false").equals("true")) cmd.add("--noupdate");
        String nvdKey = EnvConfig.get("nvd.api.key");
        if (nvdKey != null) { cmd.add("--nvdApiKey"); cmd.add(nvdKey); }
        run(cfg, cmd, null, 0, 1);
        return FileUtils.readString(file(cfg, "dependency-check-report.json"));
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode dep : MAPPER.readTree(raw).path("dependencies")) {
            for (JsonNode v : dep.path("vulnerabilities")) {
                String id = text(v, "name", "unknown");
                String cwe = v.path("cwes").isArray() && v.path("cwes").size() > 0 ? v.path("cwes").get(0).asText() : null;
                list.add(Vulnerability.builder()
                        .id(id).title(id + " in " + text(dep, "fileName", "dependency"))
                        .description(text(v, "description", null))
                        .severity(Severity.fromString(text(v, "severity", "INFO")))
                        .scanner(name()).category(category())
                        .location(text(dep, "filePath", text(dep, "fileName", "?")))
                        .cwe(cwe).cve(id.startsWith("CVE-") ? id : null)
                        .remediation("Upgrade or replace " + text(dep, "fileName", "the dependency"))
                        .build());
            }
        }
        return list;
    }
}
