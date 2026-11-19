package com.venTech.security.scanners.secrets;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class GitleaksScanner extends BaseScanner {
    @Override public String name() { return "gitleaks"; }
    @Override public Category category() { return Category.SECRETS; }
    @Override protected String requiredBinary() { return "gitleaks"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        Path out = file(cfg, "gitleaks.json");
        List<String> cmd = new ArrayList<>(List.of("gitleaks", "detect", "--source", sourcePath(cfg),
                "--report-format", "json", "--report-path", out.toString(),
                "--redact", "--no-banner", "--exit-code", "1"));
        if (cfg.option("noGit", "false").equals("true")) cmd.add("--no-git");
        run(cfg, cmd, null, 0, 1);
        return java.nio.file.Files.exists(out) ? FileUtils.readString(out) : "[]";
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode f : MAPPER.readTree(raw)) {
            list.add(Vulnerability.builder()
                    .id(text(f, "RuleID", "secret"))
                    .title(text(f, "Description", "Secret detected"))
                    .description("Commit " + text(f, "Commit", "n/a") + " by " + text(f, "Author", "n/a"))
                    .severity(Severity.HIGH)
                    .scanner(name()).category(category())
                    .location(text(f, "File", "?") + ":" + f.path("StartLine").asInt(0))
                    .cwe("CWE-798")
                    .remediation("Revoke and rotate the credential, then purge it from git history")
                    .build());
        }
        return list;
    }
}
