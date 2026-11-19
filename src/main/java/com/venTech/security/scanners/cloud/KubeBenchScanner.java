package com.venTech.security.scanners.cloud;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/** CIS Kubernetes benchmark. Must run on (or with access to) the node being assessed. */
public class KubeBenchScanner extends BaseScanner {
    @Override public String name() { return "kube-bench"; }
    @Override public Category category() { return Category.CLOUD; }
    @Override protected String requiredBinary() { return "kube-bench"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        List<String> cmd = new ArrayList<>(List.of("kube-bench", "run", "--json"));
        String targets = cfg.option("targets", "");
        if (!targets.isBlank()) { cmd.add("--targets"); cmd.add(targets); }
        String out = run(cfg, cmd, null, 0).stdout();
        FileUtils.writeString(file(cfg, "kube-bench.json"), out);
        return out;
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        JsonNode root = MAPPER.readTree(raw);
        JsonNode controls = root.has("Controls") ? root.path("Controls") : root;
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode control : controls) {
            for (JsonNode test : control.path("tests")) {
                for (JsonNode r : test.path("results")) {
                    String status = text(r, "status", "");
                    if (!status.equals("FAIL") && !status.equals("WARN")) continue;
                    list.add(Vulnerability.builder()
                            .id("CIS-" + text(r, "test_number", "?"))
                            .title(text(r, "test_desc", "CIS benchmark check"))
                            .severity(status.equals("FAIL") ? Severity.MEDIUM : Severity.LOW)
                            .scanner(name()).category(category())
                            .location("section " + text(test, "section", "?"))
                            .remediation(text(r, "remediation", null))
                            .build());
                }
            }
        }
        return list;
    }
}
