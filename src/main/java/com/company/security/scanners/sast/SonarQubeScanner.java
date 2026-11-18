package com.company.security.scanners.sast;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import com.company.security.utils.HttpUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Runs sonar-scanner, waits for the quality gate, then pulls VULNERABILITY issues over the REST API. */
public class SonarQubeScanner extends BaseScanner {
    @Override public String name() { return "sonarqube"; }
    @Override public Category category() { return Category.SAST; }
    @Override protected String requiredBinary() { return "sonar-scanner"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        String host = cfg.option("hostUrl", EnvConfig.get("sonar.host.url", "http://localhost:9000"));
        String key = cfg.option("projectKey", cfg.target().name());
        String token = EnvConfig.require("sonar.token");

        List<String> cmd = List.of("sonar-scanner",
                "-Dsonar.projectKey=" + key,
                "-Dsonar.projectBaseDir=" + sourcePath(cfg),
                "-Dsonar.sources=.",
                "-Dsonar.host.url=" + host,
                "-Dsonar.qualitygate.wait=true",
                "-Dsonar.qualitygate.timeout=600");
        // exit 1 can mean "quality gate failed"; findings are fetched below either way
        run(cfg, cmd, Map.of("SONAR_TOKEN", token), 0, 1);

        ArrayNode all = MAPPER.createArrayNode();
        String auth = HttpUtil.basicAuth(token, "");
        for (int page = 1; page <= 20; page++) {
            String url = host + "/api/issues/search?componentKeys=" + URLEncoder.encode(key, StandardCharsets.UTF_8)
                    + "&types=VULNERABILITY&resolved=false&ps=500&p=" + page;
            HttpUtil.Response r = HttpUtil.get(url, Map.of("Authorization", auth));
            if (r.status() != 200) throw new IOException("SonarQube API returned HTTP " + r.status());
            JsonNode root = MAPPER.readTree(r.body());
            root.path("issues").forEach(all::add);
            if (page * 500 >= root.path("paging").path("total").asInt()) break;
        }
        ObjectNode out = MAPPER.createObjectNode();
        out.set("issues", all);
        String json = MAPPER.writeValueAsString(out);
        FileUtils.writeString(file(cfg, "sonarqube-issues.json"), json);
        return json;
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        List<Vulnerability> list = new ArrayList<>();
        for (JsonNode i : MAPPER.readTree(raw).path("issues")) {
            String component = text(i, "component", "?");
            String path = component.contains(":") ? component.substring(component.indexOf(':') + 1) : component;
            list.add(Vulnerability.builder()
                    .id(text(i, "rule", "sonar-rule"))
                    .title(text(i, "message", "SonarQube issue"))
                    .severity(sonarSeverity(text(i, "severity", "INFO")))
                    .scanner(name()).category(category())
                    .location(path + ":" + i.path("line").asInt(0))
                    .build());
        }
        return list;
    }

    private static Severity sonarSeverity(String s) {
        return switch (s) {
            case "BLOCKER" -> Severity.CRITICAL;
            case "CRITICAL" -> Severity.HIGH;
            case "MAJOR" -> Severity.MEDIUM;
            case "MINOR" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }
}
