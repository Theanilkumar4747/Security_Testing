package com.venTech.security.reporting;

import com.venTech.security.core.ScanResult;
import com.venTech.security.core.Severity;
import com.venTech.security.model.ScanReport;
import com.venTech.security.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.HashSet;
import java.util.Set;

/** SARIF 2.1.0 - consumable by GitHub code scanning, Azure DevOps and DefectDojo. */
public class SarifReportBuilder {
    private static final ObjectMapper M = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public ObjectNode buildNode(ScanReport report) {
        ObjectNode root = M.createObjectNode();
        root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.put("version", "2.1.0");
        ArrayNode runs = root.putArray("runs");

        for (ScanResult r : report.results()) {
            if (r.vulnerabilities().isEmpty()) continue;
            ObjectNode run = runs.addObject();
            ObjectNode driver = run.putObject("tool").putObject("driver");
            driver.put("name", r.scanner());
            ArrayNode rules = driver.putArray("rules");
            ArrayNode results = run.putArray("results");
            Set<String> seen = new HashSet<>();

            for (Vulnerability v : r.vulnerabilities()) {
                String ruleId = v.id() != null ? v.id() : String.valueOf(v.title());
                if (seen.add(ruleId)) {
                    ObjectNode rule = rules.addObject();
                    rule.put("id", ruleId);
                    rule.putObject("shortDescription").put("text", String.valueOf(v.title()));
                    if (v.remediation() != null) rule.putObject("help").put("text", v.remediation());
                    rule.putObject("properties").put("security-severity", score(v.severity()));
                }
                ObjectNode res = results.addObject();
                res.put("ruleId", ruleId);
                res.put("level", level(v.severity()));
                res.putObject("message").put("text", v.title() + (v.description() != null ? " - " + v.description() : ""));
                String loc = v.location() == null ? "unknown" : v.location();
                ObjectNode phys = res.putArray("locations").addObject().putObject("physicalLocation");
                int colon = loc.lastIndexOf(':');
                boolean hasLine = colon > 0 && !loc.startsWith("http") && loc.substring(colon + 1).matches("\\d+") && !loc.endsWith(":0");
                phys.putObject("artifactLocation").put("uri", hasLine ? loc.substring(0, colon) : loc);
                if (hasLine) phys.putObject("region").put("startLine", Integer.parseInt(loc.substring(colon + 1)));
                res.putObject("partialFingerprints").put("primaryLocationLineHash", v.fingerprint());
            }
        }
        return root;
    }

    public String build(ScanReport report) throws Exception { return M.writeValueAsString(buildNode(report)); }

    private static String level(Severity s) {
        return switch (s) { case CRITICAL, HIGH -> "error"; case MEDIUM -> "warning"; default -> "note"; };
    }

    private static String score(Severity s) {
        return switch (s) { case CRITICAL -> "9.5"; case HIGH -> "8.0"; case MEDIUM -> "5.5"; case LOW -> "3.0"; default -> "0.5"; };
    }
}
