package com.company.security.scanners.secrets;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/** TruffleHog v3. Verified (live) credentials are rated CRITICAL; the raw secret is never stored. */
public class TruffleHogScanner extends BaseScanner {
    @Override public String name() { return "trufflehog"; }
    @Override public Category category() { return Category.SECRETS; }
    @Override protected String requiredBinary() { return "trufflehog"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        List<String> cmd = new ArrayList<>(List.of("trufflehog", "filesystem", sourcePath(cfg), "--json", "--no-update"));
        if (cfg.option("onlyVerified", "false").equals("true")) cmd.add("--only-verified");
        String out = run(cfg, cmd, null, 0).stdout();
        FileUtils.writeString(file(cfg, "trufflehog.jsonl"), out);
        return out;
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (String line : raw.split("\\R")) {
            if (!line.startsWith("{")) continue;
            JsonNode f = MAPPER.readTree(line);
            if (!f.has("DetectorName")) continue;
            JsonNode fs = f.path("SourceMetadata").path("Data").path("Filesystem");
            boolean verified = f.path("Verified").asBoolean(false);
            list.add(Vulnerability.builder()
                    .id("trufflehog-" + text(f, "DetectorName", "secret"))
                    .title(text(f, "DetectorName", "Secret") + (verified ? " (verified live)" : " (unverified)"))
                    .severity(verified ? Severity.CRITICAL : Severity.HIGH)
                    .scanner(name()).category(category())
                    .location(text(fs, "file", "?") + ":" + fs.path("line").asInt(0))
                    .cwe("CWE-798")
                    .remediation("Revoke and rotate the credential immediately")
                    .build());
        }
        return list;
    }
}
