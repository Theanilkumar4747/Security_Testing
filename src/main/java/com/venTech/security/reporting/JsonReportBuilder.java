package com.venTech.security.reporting;

import com.venTech.security.core.ScanResult;
import com.venTech.security.model.ScanReport;
import com.venTech.security.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class JsonReportBuilder {
    private static final ObjectMapper M = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).enable(SerializationFeature.INDENT_OUTPUT);

    public String build(ScanReport report) throws Exception {
        ObjectNode root = M.createObjectNode();
        root.put("id", report.id());
        root.put("startedAt", report.startedAt().toString());
        root.put("finishedAt", report.finishedAt().toString());
        root.set("target", M.valueToTree(report.target()));

        ObjectNode summary = root.putObject("summary");
        summary.put("total", report.vulnerabilities().size());
        summary.set("bySeverity", M.valueToTree(report.countBySeverity()));

        ArrayNode scanners = root.putArray("scanners");
        for (ScanResult r : report.results()) {
            ObjectNode n = scanners.addObject();
            n.put("scanner", r.scanner());
            n.put("category", r.category().name());
            n.put("status", r.status().name());
            n.put("durationMs", r.durationMs());
            n.put("findings", r.vulnerabilities().size());
            if (r.message() != null) n.put("message", r.message());
        }
        ArrayNode vulns = root.putArray("vulnerabilities");
        for (Vulnerability v : report.vulnerabilities()) vulns.add(M.valueToTree(v));
        return M.writeValueAsString(root);
    }
}
