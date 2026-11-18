package com.company.security.reporting;

import com.company.security.model.ScanReport;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import com.company.security.utils.HttpUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * Publishes results. dashboard.type = none | filesystem | http.
 * filesystem: copies reports to dashboard.dir/&lt;run&gt;/ and /latest/ and maintains history.json for trend charts.
 * http: POSTs the JSON report to dashboard.url (Bearer dashboard.token).
 */
public class DashboardPublisher {
    private static final ObjectMapper M = new ObjectMapper();

    public void publish(ScanReport report, Map<String, Path> artifacts) throws Exception {
        switch (EnvConfig.get("dashboard.type", "none").toLowerCase()) {
            case "filesystem" -> toFilesystem(report, artifacts);
            case "http" -> toHttp(report, artifacts);
            default -> { }
        }
    }

    private void toFilesystem(ScanReport report, Map<String, Path> artifacts) throws IOException {
        Path root = Path.of(EnvConfig.require("dashboard.dir"));
        String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC).format(report.finishedAt());
        Path runDir = root.resolve(stamp + "-" + report.id());
        for (Path src : artifacts.values()) {
            FileUtils.copy(src, runDir.resolve(src.getFileName()));
            FileUtils.copy(src, root.resolve("latest").resolve(src.getFileName()));
        }
        Path history = root.resolve("history.json");
        ArrayNode arr = Files.exists(history) ? (ArrayNode) M.readTree(FileUtils.readString(history)) : M.createArrayNode();
        ObjectNode entry = arr.addObject();
        entry.put("id", report.id()).put("target", report.target().name()).put("finishedAt", report.finishedAt().toString());
        entry.set("bySeverity", M.valueToTree(report.countBySeverity()));
        FileUtils.writeString(history, M.writerWithDefaultPrettyPrinter().writeValueAsString(arr));
    }

    private void toHttp(ScanReport report, Map<String, Path> artifacts) throws Exception {
        Path json = artifacts.get("json");
        if (json == null) throw new IllegalStateException("http dashboard needs the 'json' report format");
        String token = EnvConfig.get("dashboard.token", "");
        Map<String, String> headers = token.isBlank() ? Map.of() : Map.of("Authorization", "Bearer " + token);
        HttpUtil.Response r = HttpUtil.postJson(EnvConfig.require("dashboard.url"), headers, FileUtils.readString(json));
        if (r.status() >= 300) throw new IOException("Dashboard returned HTTP " + r.status());
    }
}
