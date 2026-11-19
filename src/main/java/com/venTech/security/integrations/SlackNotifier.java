package com.venTech.security.integrations;

import com.venTech.security.core.Severity;
import com.venTech.security.gate.QualityGate;
import com.venTech.security.model.ScanReport;
import com.venTech.security.utils.EnvConfig;
import com.venTech.security.utils.HttpUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;

/** Posts a summary to a Slack incoming webhook (SLACK_WEBHOOK_URL). */
public class SlackNotifier {
    private static final ObjectMapper M = new ObjectMapper();
    private final String webhook;

    public SlackNotifier(String webhook) { this.webhook = webhook; }

    public static SlackNotifier fromEnv() { return new SlackNotifier(EnvConfig.require("slack.webhook.url")); }

    public void notifyScan(ScanReport report, QualityGate.GateResult gate) throws IOException, InterruptedException {
        Map<Severity, Long> c = report.countBySeverity();
        StringBuilder t = new StringBuilder(gate.passed() ? ":white_check_mark: *Security gate passed* " : ":rotating_light: *Security gate FAILED* ")
                .append("for `").append(report.target().name()).append("`\n")
                .append("Critical: ").append(c.get(Severity.CRITICAL)).append(" | High: ").append(c.get(Severity.HIGH))
                .append(" | Medium: ").append(c.get(Severity.MEDIUM)).append(" | Low: ").append(c.get(Severity.LOW));
        gate.violations().stream().limit(8).forEach(v -> t.append("\n• ").append(v));
        String build = EnvConfig.get("build.url", "");
        if (!build.isBlank()) t.append("\n<").append(build).append("|Open build>");
        HttpUtil.Response r = HttpUtil.postJson(webhook, null, M.writeValueAsString(Map.of("text", t.toString())));
        if (r.status() >= 300) throw new IOException("Slack returned HTTP " + r.status());
    }
}
