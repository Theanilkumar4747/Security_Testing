package com.company.security.integrations;

import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.HttpUtil;
import com.company.security.utils.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Creates one Jira issue per unique finding at or above a severity, de-duplicated with a label
 * "sec-&lt;fingerprint&gt;" so re-runs never create duplicates. Jira Cloud users: set jira.search.path=/rest/api/3/search/jql.
 */
public class JiraClient {
    private static final Logger LOG = Logger.get(JiraClient.class);
    private static final ObjectMapper M = new ObjectMapper();

    private final String baseUrl, projectKey, issueType, searchPath;
    private final Map<String, String> headers;

    private JiraClient(String baseUrl, String user, String token, String projectKey, String issueType, String searchPath) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.projectKey = projectKey;
        this.issueType = issueType;
        this.searchPath = searchPath;
        this.headers = Map.of("Authorization", HttpUtil.basicAuth(user, token), "Accept", "application/json");
    }

    public static JiraClient fromEnv() {
        return new JiraClient(EnvConfig.require("jira.url"), EnvConfig.require("jira.user"), EnvConfig.require("jira.token"),
                EnvConfig.require("jira.project"), EnvConfig.get("jira.issue.type", "Bug"),
                EnvConfig.get("jira.search.path", "/rest/api/2/search"));
    }

    /** @return number of issues created */
    public int createIssues(List<Vulnerability> vulns, Severity min, int max) throws IOException, InterruptedException {
        int created = 0;
        Set<String> seen = new HashSet<>();
        for (Vulnerability v : vulns) {
            if (created >= max) break;
            if (!v.severity().atLeast(min) || !seen.add(v.fingerprint())) continue;
            if (exists(v.fingerprint())) continue;
            create(v);
            created++;
        }
        LOG.info("Jira: created {} issue(s)", created);
        return created;
    }

    private boolean exists(String fingerprint) throws IOException, InterruptedException {
        String jql = "project = \"" + projectKey + "\" AND labels = \"sec-" + fingerprint + "\" AND statusCategory != Done";
        HttpUtil.Response r = HttpUtil.get(baseUrl + searchPath + "?maxResults=1&jql=" + URLEncoder.encode(jql, StandardCharsets.UTF_8), headers);
        if (r.status() != 200) throw new IOException("Jira search returned HTTP " + r.status());
        return M.readTree(r.body()).path("issues").size() > 0;
    }

    private void create(Vulnerability v) throws IOException, InterruptedException {
        ObjectNode fields = M.createObjectNode();
        fields.putObject("project").put("key", projectKey);
        fields.putObject("issuetype").put("name", issueType);
        fields.put("summary", ("[" + v.severity() + "] " + v.title()).substring(0, Math.min(250, ("[" + v.severity() + "] " + v.title()).length())));
        fields.put("description", "Scanner: " + v.scanner() + "\nLocation: " + v.location() + "\nID: " + v.id()
                + (v.cve() != null ? "\nCVE: " + v.cve() : "") + (v.cwe() != null ? "\nCWE: " + v.cwe() : "")
                + "\n\n" + (v.description() == null ? "" : v.description())
                + "\n\nRemediation: " + (v.remediation() == null ? "see scanner documentation" : v.remediation()));
        fields.putArray("labels").add("security").add("automated-scan").add("sec-" + v.fingerprint());
        ObjectNode body = M.createObjectNode();
        body.set("fields", fields);
        HttpUtil.Response r = HttpUtil.postJson(baseUrl + "/rest/api/2/issue", headers, M.writeValueAsString(body));
        if (r.status() >= 300) throw new IOException("Jira create returned HTTP " + r.status() + ": " + r.body());
    }
}
