package com.venTech.security.scanners.sca;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Trivy: filesystem (default) or container image scan (option mode=image or target.imageName set). */
public class TrivyScanner extends BaseScanner {
    @Override public String name() { return "trivy"; }
    @Override public Category category() { return Category.SCA; }
    @Override protected String requiredBinary() { return "trivy"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Path out = file(cfg, "trivy.json");
        boolean image = "image".equalsIgnoreCase(cfg.option("mode", "fs"))
                && cfg.target().imageName() != null && !cfg.target().imageName().isBlank();
        List<String> cmd = new ArrayList<>(List.of("trivy", image ? "image" : "fs",
                "--format", "json", "--output", out.toString(),
                "--scanners", cfg.option("scanners", "vuln,secret,misconfig"),
                "--severity", cfg.option("severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
                "--quiet"));
        if (cfg.option("ignoreUnfixed", "false").equals("true")) cmd.add("--ignore-unfixed");
        cmd.add(image ? cfg.target().imageName() : sourcePath(cfg));
        run(cfg, cmd, null, 0);
        return FileUtils.readString(out);
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode res : MAPPER.readTree(raw).path("Results")) {
            String target = text(res, "Target", "?");
            for (JsonNode v : res.path("Vulnerabilities")) {
                String id = text(v, "VulnerabilityID", "unknown");
                String fixed = text(v, "FixedVersion", null);
                list.add(Vulnerability.builder()
                        .id(id).title(text(v, "Title", id + " in " + text(v, "PkgName", "package")))
                        .description(text(v, "Description", null))
                        .severity(Severity.fromString(text(v, "Severity", "INFO")))
                        .scanner(name()).category(category())
                        .location(target + " :: " + text(v, "PkgName", "?") + "@" + text(v, "InstalledVersion", "?"))
                        .cve(id.startsWith("CVE-") ? id : null)
                        .remediation(fixed == null ? null : "Upgrade to " + fixed)
                        .build());
            }
            for (JsonNode m : res.path("Misconfigurations")) {
                list.add(Vulnerability.builder()
                        .id(text(m, "ID", "misconfig")).title(text(m, "Title", "Misconfiguration"))
                        .description(text(m, "Message", null))
                        .severity(Severity.fromString(text(m, "Severity", "INFO")))
                        .scanner(name()).category(category()).location(target)
                        .remediation(text(m, "Resolution", null)).build());
            }
            for (JsonNode s : res.path("Secrets")) {
                list.add(Vulnerability.builder()
                        .id(text(s, "RuleID", "secret")).title(text(s, "Title", "Secret detected"))
                        .severity(Severity.fromString(text(s, "Severity", "HIGH")))
                        .scanner(name()).category(category())
                        .location(target + ":" + s.path("StartLine").asInt(0))
                        .remediation("Revoke and rotate the credential; remove it from source control").build());
            }
        }
        return list;
    }
}
