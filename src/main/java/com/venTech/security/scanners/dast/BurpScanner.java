package com.venTech.security.scanners.dast;

import com.venTech.security.core.BaseScanner;
import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.Severity;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.EnvConfig;
import com.venTech.security.utils.FileUtils;
import com.venTech.security.utils.HttpUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Burp Suite Professional REST API (burp.api.url, default http://127.0.0.1:1337 + optional burp.api.key).
 * Burp must already be running with the REST API enabled; this class launches a scan and polls it.
 * Endpoint shapes follow Burp's v0.1 scan API - verify against your Burp version.
 */
public class BurpScanner extends BaseScanner {
    @Override public String name() { return "burp"; }
    @Override public Category category() { return Category.DAST; }

    private String base() {
        String url = EnvConfig.get("burp.api.url", "http://127.0.0.1:1337");
        String key = EnvConfig.get("burp.api.key", "");
        return key.isBlank() ? url + "/v0.1" : url + "/" + key + "/v0.1";
    }

    @Override
    public boolean isAvailable() {
        try { return HttpUtil.get(base() + "/", null).status() < 500; }
        catch (Exception e) { return false; }
    }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        ObjectNode body = MAPPER.createObjectNode();
        body.putArray("urls").add(cfg.target().url());
        HttpUtil.Response created = HttpUtil.postJson(base() + "/scan", null, MAPPER.writeValueAsString(body));
        String location = created.header("Location");
        if (created.status() != 201 || location == null) throw new IOException("Burp refused scan: HTTP " + created.status());
        String taskId = location.substring(location.lastIndexOf('/') + 1);

        Instant deadline = Instant.now().plus(cfg.timeout());
        while (Instant.now().isBefore(deadline)) {
            HttpUtil.Response r = HttpUtil.get(base() + "/scan/" + taskId, Map.of());
            JsonNode root = MAPPER.readTree(r.body());
            String status = text(root, "scan_status", "");
            if (status.equals("succeeded") || status.equals("failed") || status.equals("paused")) {
                if (status.equals("failed")) throw new IOException("Burp scan failed");
                FileUtils.writeString(file(cfg, "burp.json"), r.body());
                return r.body();
            }
            Thread.sleep(Duration.ofSeconds(15).toMillis());
        }
        throw new java.util.concurrent.TimeoutException("Burp scan " + taskId);
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode ev : MAPPER.readTree(raw).path("issue_events")) {
            JsonNode i = ev.path("issue");
            if (i.isMissingNode()) continue;
            list.add(Vulnerability.builder()
                    .id("burp-" + text(i, "type_index", text(i, "name", "issue")))
                    .title(text(i, "name", "Burp issue"))
                    .description(stripHtml(text(i, "description", null)))
                    .severity(Severity.fromString(text(i, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(text(i, "origin", "") + text(i, "path", ""))
                    .build());
        }
        return list;
    }
}
