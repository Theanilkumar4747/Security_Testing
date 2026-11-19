package com.venTech.security.reporting;

import com.venTech.security.core.ScanResult;
import com.venTech.security.core.Severity;
import com.venTech.security.gate.QualityGate;
import com.venTech.security.model.ScanReport;
import com.venTech.security.model.Vulnerability;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/** Self-contained Extent-style HTML dashboard. All dynamic text is escaped. */
public class HtmlReportBuilder {
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*\\b");
    private static final Pattern BEARER = Pattern.compile("(?i)\\bBearer\\s+[A-Za-z0-9._~+/-]+=*");
    private static final Pattern COOKIE_HEADER = Pattern.compile("(?i)\\b(?:Cookie|Set-Cookie)\\s*:\\s*[^\\r\\n]*");
    private static final Pattern CREDENTIAL = Pattern.compile(
            "(?i)\\b(password|passwd|passphrase|access[_-]?token|refresh[_-]?token|id[_-]?token(?:[_-]?hint)?|auth[_-]?token|client[_-]?secret|token|secret|api[_-]?key|authorization|cookie|session(?:[_-]?id)?|jwt)(\\s*[=:]\\s*)(?:\"[^\"]*\"|'[^']*'|[^&\\s,;\"'<>]+)");
    private static final List<String> TRACKING_STATUSES =
            List.of("Open", "In Progress", "Fixed", "Accepted Risk", "False Positive");

    public String build(ScanReport report) {
        return build(report, null);
    }

    public String build(ScanReport report, QualityGate.GateResult gate) {
        long elapsedMs = Math.max(0, Duration.between(report.startedAt(), report.finishedAt()).toMillis());
        long passed = report.results().stream().filter(r -> r.status() == ScanResult.Status.SUCCESS).count();
        long failed = report.results().stream().filter(r -> r.status() == ScanResult.Status.FAILED).count();
        long skipped = report.results().stream().filter(r -> r.status() == ScanResult.Status.SKIPPED).count();
        String overall = failed > 0 || (gate != null && !gate.passed()) ? "FAILED" : "PASSED";

        StringBuilder h = new StringBuilder(12000);
        h.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<title>Security Scan Report - ").append(esc(report.target().name())).append("</title><style>")
                .append(":root{color-scheme:light;--ink:#202938;--muted:#697586;--line:#e3e8ef;--blue:#4263eb}")
                .append("*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}")
                .append(".top{background:#172554;color:#fff;padding:28px max(24px,calc((100% - 1180px)/2))}")
                .append(".top h1{margin:0;font-size:25px}.meta{color:#cbd5e1;margin-top:8px;overflow-wrap:anywhere}")
                .append("main{max-width:1180px;margin:24px auto;padding:0 20px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}")
                .append(".box,.panel,.test{background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 2px 8px #1725540a}")
                .append(".box{padding:16px 18px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}")
                .append(".value{font-size:26px;font-weight:700;margin-top:4px}.PASSED{color:#16803c}.FAILED{color:#c92a2a}.SKIPPED{color:#687385}")
                .append(".sev-CRITICAL{color:#a20d25}.sev-HIGH{color:#d12e35}.sev-MEDIUM{color:#a56b00}.sev-LOW{color:#1769aa}.sev-INFO{color:#687385}")
                .append("section{margin-top:24px}h2{font-size:18px;margin:0 0 12px}.panel{padding:18px}")
                .append(".tests{display:grid;gap:10px}.test{padding:14px 16px;box-shadow:none}.test-head{display:flex;justify-content:space-between;gap:12px;align-items:center}")
                .append(".test-name{font-weight:650;font-size:15px}.pill{border-radius:999px;padding:3px 10px;font-size:12px;font-weight:700;background:#eef1f5}")
                .append(".details{color:var(--muted);margin-top:6px}.message{margin-top:8px;padding:8px 10px;background:#f7f8fa;border-radius:6px;overflow-wrap:anywhere}")
                .append(".charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px}.chart{min-width:0}")
                .append(".chart svg{display:block;width:100%;height:auto;max-height:420px}.chart text{font-family:system-ui,-apple-system,Segoe UI,sans-serif}")
                .append(".guidance{color:var(--muted);margin:0 0 12px}.priority{border-left:4px solid #d12e35;padding:12px 14px;margin:10px 0;background:#fff8f8;border-radius:4px}.priority h3{margin:0 0 5px;font-size:15px}.priority p{margin:5px 0}")
                .append(".filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px}.filters input,.filters select,.tracker-fields input,.tracker-fields select{font:inherit;padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;min-width:150px}")
                .append(".tracker-tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0 14px}.tracker-tools button{font:inherit;padding:8px 12px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;cursor:pointer}.tracker-fields{display:flex;gap:12px;flex-wrap:wrap;padding:12px 0}.tracker-fields label{display:grid;gap:4px}.tracker-message{min-height:1.5em;color:#1769aa}.detail-row>td{background:#f8fafc}.finding-details summary{cursor:pointer;color:#2850b8;font-weight:600}")
                .append("table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}")
                .append("th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}footer{color:var(--muted);font-size:12px;padding:28px 0}")
                .append("@media(max-width:650px){main{padding:0 12px}.panel{overflow-x:auto}.top{padding:22px 16px}}")
                .append("</style></head><body><header class=\"top\"><h1>Security Scan Report</h1><div class=\"meta\">Target: <b>")
                .append(esc(report.target().name())).append("</b>");
        if (report.target().url() != null && !report.target().url().isBlank()) {
            h.append(" &middot; URL: ").append(esc(report.target().url()));
        }
        h.append(" &middot; Run ID: ").append(esc(report.id())).append("</div><div class=\"meta\">Started ")
                .append(esc(report.startedAt().toString())).append(" &middot; Finished ")
                .append(esc(report.finishedAt().toString())).append(" &middot; Duration ")
                .append(duration(elapsedMs)).append("</div></header><main>");

        h.append("<div class=\"summary\">");
        card(h, "Overall result", overall, overall);
        card(h, "Scanners passed", String.valueOf(passed), "PASSED");
        card(h, "Scanners failed", String.valueOf(failed), failed > 0 ? "FAILED" : "");
        card(h, "Scanners skipped", String.valueOf(skipped), "SKIPPED");
        card(h, "Total findings", String.valueOf(report.vulnerabilities().size()), "");
        for (Severity severity : Severity.values()) {
            card(h, severity.name() + " findings", String.valueOf(report.countBySeverity().getOrDefault(severity, 0L)),
                    "sev-" + severity.name());
        }
        h.append("</div>");

        h.append("<section><h2>Visual summary</h2><div class=\"charts\">")
                .append("<div class=\"panel chart\"><h3>Findings by severity</h3>")
                .append(severityChart(report)).append("</div>")
                .append("<div class=\"panel chart\"><h3>Findings by scanner</h3>")
                .append(scannerChart(report)).append("</div></div></section>");

        h.append("<section><h2>How to read this report</h2><div class=\"panel\"><p class=\"guidance\">")
                .append("<b class=\"sev-CRITICAL\">Critical:</b> address immediately. ")
                .append("<b class=\"sev-HIGH\">High:</b> fix as soon as possible. ")
                .append("<b class=\"sev-MEDIUM\">Medium:</b> plan a timely fix. ")
                .append("<b class=\"sev-LOW\">Low:</b> improve when practical. ")
                .append("<b class=\"sev-INFO\">Info:</b> review for context.</p></div></section>");

        List<Vulnerability> priorities = sortedFindings(report).stream()
                .filter(v -> v.severity() == Severity.CRITICAL || v.severity() == Severity.HIGH).toList();
        h.append("<section><h2>Start here: highest-priority fixes</h2>");
        if (priorities.isEmpty()) {
            h.append("<div class=\"panel\">No Critical or High findings. Review the remaining findings below.</div>");
        } else {
            h.append("<div class=\"tests\">");
            for (Vulnerability v : priorities) {
                h.append("<article class=\"priority\"><h3><span class=\"sev-").append(v.severity()).append("\">")
                        .append(v.severity()).append("</span> &middot; ").append(esc(v.title())).append("</h3>")
                        .append("<p><b>Where:</b> ").append(esc(v.location())).append("</p>");
                if (v.description() != null && !v.description().isBlank()) {
                    h.append("<p><b>Why it matters:</b> ").append(esc(v.description())).append("</p>");
                }
                if (v.remediation() != null && !v.remediation().isBlank()) {
                    h.append("<p><b>Suggested fix:</b> ").append(esc(v.remediation())).append("</p>");
                }
                h.append("</article>");
            }
            h.append("</div>");
        }
        h.append("</section>");

        h.append("<section><h2>Execution details</h2><div class=\"tests\">");
        for (ScanResult result : report.results()) {
            h.append("<article class=\"test\"><div class=\"test-head\"><span class=\"test-name\">")
                    .append(esc(result.scanner())).append(" <span class=\"details\">&middot; ")
                    .append(result.category()).append("</span></span><span class=\"pill ")
                    .append(result.status()).append("\">").append(result.status()).append("</span></div><div class=\"details\">")
                    .append(result.vulnerabilities().size()).append(" finding(s) &middot; ")
                    .append(duration(result.durationMs())).append("</div>");
            if (result.message() != null && !result.message().isBlank()) {
                h.append("<div class=\"message\">").append(esc(result.message())).append("</div>");
            }
            h.append("</article>");
        }
        if (report.results().isEmpty()) h.append("<div class=\"panel\">No scanners were executed.</div>");
        h.append("</div></section>");

        if (gate != null) {
            h.append("<section><h2>Quality gate</h2><div class=\"panel\"><b class=\"")
                    .append(gate.passed() ? "PASSED" : "FAILED").append("\">")
                    .append(gate.passed() ? "PASSED" : "FAILED").append("</b> &middot; ")
                    .append(gate.suppressed()).append(" finding(s) suppressed");
            if (!gate.violations().isEmpty()) {
                h.append("<ul>");
                for (String violation : gate.violations()) h.append("<li>").append(esc(violation)).append("</li>");
                h.append("</ul>");
            }
            h.append("</div></section>");
        }

        List<Vulnerability> sorted = sortedFindings(report);
        h.append("<section id=\"findings\"><h2>All findings</h2><div class=\"panel\" id=\"finding-panel\" data-tracker-scope=\"")
                .append(trackingScope(report)).append("\">")
                .append("<p class=\"guidance\">Finding status and ownership are saved in this browser. Export/import the tracker JSON to move them between browsers or reports.</p>")
                .append("<div class=\"tracker-tools\"><button id=\"export-tracker\" type=\"button\">Export tracker JSON</button>")
                .append("<label>Import tracker JSON <input id=\"import-tracker\" type=\"file\" accept=\"application/json,.json\"></label>")
                .append("<span id=\"tracker-message\" class=\"tracker-message\" role=\"status\" aria-live=\"polite\"></span></div>")
                .append("<label for=\"finding-search\">Search findings</label><div class=\"filters\">")
                .append("<input id=\"finding-search\" type=\"search\" placeholder=\"Search by title, endpoint, evidence, scanner, or fix\">")
                .append("<select id=\"filter-severity\" aria-label=\"Filter by severity\"><option value=\"\">All severities</option>");
        for (Severity severity : Severity.values()) {
            h.append("<option value=\"").append(severity).append("\">").append(severity).append("</option>");
        }
        h.append("</select><select id=\"filter-status\" aria-label=\"Filter by tracking status\"><option value=\"\">All statuses</option>");
        for (String status : TRACKING_STATUSES) {
            h.append("<option value=\"").append(esc(status)).append("\">").append(esc(status)).append("</option>");
        }
        h.append("</select><select id=\"filter-scanner\" aria-label=\"Filter by scanner\"><option value=\"\">All scanners</option>");
        report.vulnerabilities().stream().map(Vulnerability::scanner).filter(s -> s != null).distinct().sorted()
                .forEach(scanner -> h.append("<option value=\"").append(esc(scanner)).append("\">")
                        .append(esc(scanner)).append("</option>"));
        h.append("</select></div><table><thead><tr>")
                .append("<th>Finding ID</th><th>Vulnerability</th><th>Severity</th><th>Endpoint</th>")
                .append("<th>Evidence</th><th>Expected result</th><th>Actual result</th>")
                .append("<th>Recommendation</th><th>Status</th>")
                .append("</tr></thead><tbody>");
        for (Vulnerability v : sorted) {
            String trackingId = v.fingerprint();
            String endpoint = (v.httpMethod() == null || v.httpMethod().isBlank() ? "" : v.httpMethod() + " ")
                    + value(v.location());
            String status = TRACKING_STATUSES.contains(v.status()) ? v.status() : "Open";
            h.append("<tr data-finding-row data-id=\"").append(trackingId).append("\" data-status=\"")
                    .append(esc(status)).append("\" data-severity=\"").append(v.severity())
                    .append("\" data-scanner=\"").append(esc(value(v.scanner()))).append("\" data-endpoint=\"")
                    .append(esc(endpoint)).append("\"><td>").append(esc(v.findingId())).append("<br><small>Rule: ")
                    .append(esc(value(v.id()))).append("</small></td><td>").append(esc(value(v.title())))
                    .append("</td><td class=\"sev-").append(v.severity()).append("\"><b>").append(v.severity())
                    .append("</b></td><td>").append(esc(endpoint)).append("</td><td>")
                    .append(esc(value(v.evidence()))).append("</td><td>")
                    .append(esc(value(v.expectedResult()))).append("</td><td>")
                    .append(esc(value(v.actualResult()))).append("</td><td>")
                    .append(esc(value(v.remediation()))).append("</td><td data-status-cell>").append(esc(status))
                    .append("</td></tr><tr class=\"detail-row\" data-detail-row data-id=\"").append(trackingId)
                    .append("\"><td colspan=\"9\"><details class=\"finding-details\"><summary>View details and update tracking</summary>")
                    .append("<p><b>Scanner:</b> ").append(esc(value(v.scanner()))).append(" &middot; <b>Category:</b> ")
                    .append(esc(v.category() == null ? "Not provided by scanner" : v.category().name()))
                    .append(" &middot; <b>CVE/CWE:</b> ").append(esc(join(v.cve(), v.cwe())))
                    .append("</p><p><b>Description:</b> ").append(esc(value(v.description()))).append("</p>")
                    .append("<div class=\"tracker-fields\"><label>Status<select data-field=\"status\">");
            for (String option : TRACKING_STATUSES) {
                h.append("<option value=\"").append(esc(option)).append("\"")
                        .append(option.equals(status) ? " selected" : "").append(">").append(esc(option)).append("</option>");
            }
            h.append("</select></label><label>Owner<input data-field=\"owner\" type=\"text\" maxlength=\"120\" placeholder=\"Assign an owner\"></label>")
                    .append("<label>Due date<input data-field=\"dueDate\" type=\"date\"></label>")
                    .append("<label>Retest result<input data-field=\"retest\" type=\"text\" maxlength=\"500\" placeholder=\"Not retested\"></label></div>")
                    .append("</details></td></tr>");
        }
        if (sorted.isEmpty()) h.append("<tr><td colspan=\"9\">No findings.</td></tr>");
        return h.append("</tbody></table></div></section><footer>Generated by Security Automation Framework</footer></main>")
                .append(trackerScript())
                .append("</body></html>").toString();
    }

    private static List<Vulnerability> sortedFindings(ScanReport report) {
        return report.vulnerabilities().stream()
                .sorted(Comparator.comparing((Vulnerability v) -> v.severity().weight()).reversed()).toList();
    }

    private static String trackerScript() {
        return """
                <script>
                (() => {
                  const panel = document.getElementById('finding-panel');
                  const scope = panel.dataset.trackerScope;
                  const storageKey = 'security-report-tracker:' + scope;
                  const statuses = ['Open', 'In Progress', 'Fixed', 'Accepted Risk', 'False Positive'];
                  const message = document.getElementById('tracker-message');
                  let tracker = Object.create(null);
                  const rows = [...document.querySelectorAll('[data-finding-row]')];
                  const detailsFor = id => document.querySelector('[data-detail-row][data-id="' + id + '"]');
                  const say = text => { message.textContent = text; };
                  const normalize = value => {
                    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Tracker data must be an object.');
                    const clean = Object.create(null);
                    Object.keys(value).forEach(id => {
                      const item = value[id];
                      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid tracker entry.');
                      clean[id] = {
                        status: statuses.includes(item.status) ? item.status : 'Open',
                        owner: typeof item.owner === 'string' ? item.owner.slice(0, 120) : '',
                        dueDate: typeof item.dueDate === 'string' ? item.dueDate.slice(0, 10) : '',
                        retest: typeof item.retest === 'string' ? item.retest.slice(0, 500) : ''
                      };
                    });
                    return clean;
                  };
                  const applyTracker = () => {
                    rows.forEach(row => {
                      const id = row.dataset.id;
                      const details = detailsFor(id);
                      const state = tracker[id];
                      if (!details || !state) return;
                      details.querySelector('[data-field="status"]').value = state.status;
                      details.querySelector('[data-field="owner"]').value = state.owner;
                      details.querySelector('[data-field="dueDate"]').value = state.dueDate;
                      details.querySelector('[data-field="retest"]').value = state.retest;
                      row.dataset.status = state.status;
                      row.querySelector('[data-status-cell]').textContent = state.status;
                    });
                  };
                  const filter = () => {
                    const term = document.getElementById('finding-search').value.toLowerCase();
                    const severity = document.getElementById('filter-severity').value;
                    const status = document.getElementById('filter-status').value;
                    const scanner = document.getElementById('filter-scanner').value;
                    rows.forEach(row => {
                      const detail = detailsFor(row.dataset.id);
                      const matches = (!term || (row.textContent + (detail?.textContent || '')).toLowerCase().includes(term))
                        && (!severity || row.dataset.severity === severity)
                        && (!status || row.dataset.status === status)
                        && (!scanner || row.dataset.scanner === scanner);
                      row.hidden = !matches;
                      if (detail) detail.hidden = !matches;
                    });
                  };
                  const persist = () => {
                    try {
                      localStorage.setItem(storageKey, JSON.stringify(tracker));
                      say('Tracker saved in this browser. Export JSON to keep a backup or share it.');
                    } catch (error) {
                      say('Could not save tracker in this browser: ' + error.message);
                    }
                  };
                  try {
                    const stored = localStorage.getItem(storageKey);
                    if (stored) tracker = normalize(JSON.parse(stored));
                    applyTracker();
                    if (stored) say('Saved tracker loaded from this browser.');
                  } catch (error) {
                    say('Saved tracker could not be loaded: ' + error.message + ' Import a valid tracker JSON to restore it.');
                  }
                  document.querySelectorAll('[data-field]').forEach(input => {
                    const saveField = () => {
                      const details = input.closest('[data-detail-row]');
                      const id = details.dataset.id;
                      const values = Object.fromEntries([...details.querySelectorAll('[data-field]')]
                        .map(field => [field.dataset.field, field.value]));
                      tracker[id] = {status: values.status, owner: values.owner, dueDate: values.dueDate, retest: values.retest};
                      applyTracker();
                      persist();
                      filter();
                    };
                    input.addEventListener('input', saveField);
                    input.addEventListener('change', saveField);
                  });
                  ['finding-search', 'filter-severity', 'filter-status', 'filter-scanner'].forEach(id =>
                    document.getElementById(id).addEventListener('input', filter));
                  document.getElementById('export-tracker').addEventListener('click', () => {
                    const data = JSON.stringify({schemaVersion: 1, targetScope: scope, findings: tracker}, null, 2);
                    const url = URL.createObjectURL(new Blob([data], {type: 'application/json'}));
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = 'security-findings-tracker-' + scope + '.json';
                    link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                    say('Tracker JSON exported.');
                  });
                  document.getElementById('import-tracker').addEventListener('change', event => {
                    const file = event.target.files[0];
                    if (!file) return;
                    const reader = new FileReader();
                    reader.onload = () => {
                      try {
                        const imported = JSON.parse(reader.result);
                        if (imported.schemaVersion !== 1 || imported.targetScope !== scope) {
                          throw new Error('This tracker belongs to a different target or has an unsupported version.');
                        }
                        tracker = normalize(imported.findings);
                        applyTracker();
                        persist();
                        filter();
                      } catch (error) {
                        say('Tracker import failed: ' + error.message);
                      } finally {
                        event.target.value = '';
                      }
                    };
                    reader.onerror = () => say('Tracker import failed: the selected file could not be read.');
                    reader.readAsText(file);
                  });
                  filter();
                })();
                </script>
                """;
    }

    private static String trackingScope(ScanReport report) {
        String identity = String.join("|", report.target().name() == null ? "" : report.target().name(),
                report.target().url() == null ? "" : report.target().url());
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(identity.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void card(StringBuilder h, String label, String value, String style) {
        h.append("<div class=\"box\"><div class=\"label\">").append(esc(label)).append("</div><div class=\"value ")
                .append(style).append("\">").append(esc(value)).append("</div></div>");
    }

    private static String severityChart(ScanReport report) {
        Severity[] severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO};
        String[] colors = {"#a20d25", "#d12e35", "#a56b00", "#1769aa", "#687385"};
        long max = 1;
        for (Severity severity : severities) max = Math.max(max, report.countBySeverity().getOrDefault(severity, 0L));
        StringBuilder svg = new StringBuilder("<svg viewBox=\"0 0 640 250\" role=\"img\" aria-label=\"Bar chart of findings by severity\">");
        for (int i = 0; i < severities.length; i++) {
            int y = 22 + i * 44;
            long count = report.countBySeverity().getOrDefault(severities[i], 0L);
            int width = (int) Math.round(390.0 * count / max);
            svg.append("<text x=\"4\" y=\"").append(y + 17).append("\" fill=\"#202938\" font-size=\"13\">")
                    .append(severities[i]).append("</text><rect x=\"105\" y=\"").append(y)
                    .append("\" width=\"").append(width).append("\" height=\"25\" rx=\"5\" fill=\"")
                    .append(colors[i]).append("\"/><text x=\"").append(115 + width).append("\" y=\"")
                    .append(y + 18).append("\" fill=\"#202938\" font-size=\"13\">").append(count).append("</text>");
        }
        return svg.append("</svg>").toString();
    }

    private static String scannerChart(ScanReport report) {
        List<ScanResult> results = report.results();
        int height = Math.max(80, 42 * results.size() + 24);
        long max = Math.max(1, results.stream().mapToLong(r -> r.vulnerabilities().size()).max().orElse(0));
        StringBuilder svg = new StringBuilder("<svg viewBox=\"0 0 640 ")
                .append(height).append("\" role=\"img\" aria-label=\"Bar chart of findings by scanner\">");
        if (results.isEmpty()) {
            return svg.append("<text x=\"8\" y=\"36\" fill=\"#697586\" font-size=\"14\">No scanner results</text></svg>").toString();
        }
        for (int i = 0; i < results.size(); i++) {
            ScanResult result = results.get(i);
            int y = 14 + i * 42;
            int width = (int) Math.round(390.0 * result.vulnerabilities().size() / max);
            svg.append("<text x=\"4\" y=\"").append(y + 17).append("\" fill=\"#202938\" font-size=\"13\">")
                    .append(esc(result.scanner())).append("</text><rect x=\"145\" y=\"").append(y)
                    .append("\" width=\"").append(width).append("\" height=\"25\" rx=\"5\" fill=\"")
                    .append(result.status() == ScanResult.Status.FAILED ? "#d12e35" : "#4263eb")
                    .append("\"/><text x=\"").append(155 + width).append("\" y=\"").append(y + 18)
                    .append("\" fill=\"#202938\" font-size=\"13\">").append(result.vulnerabilities().size())
                    .append("</text>");
        }
        return svg.append("</svg>").toString();
    }

    private static String duration(long ms) {
        return ms < 1000 ? ms + " ms" : String.format(java.util.Locale.ROOT, "%.2f s", ms / 1000.0);
    }

    private static String value(String s) {
        return s == null || s.isBlank() ? "Not provided by scanner" : s;
    }

    private static String join(String first, String second) {
        if (first == null || first.isBlank()) return value(second);
        return second == null || second.isBlank() ? first : first + " / " + second;
    }

    static String esc(String s) {
        if (s == null) return "";
        String redacted = BEARER.matcher(s).replaceAll("Bearer [REDACTED]");
        redacted = COOKIE_HEADER.matcher(redacted).replaceAll("Cookie: [REDACTED]");
        redacted = JWT.matcher(redacted).replaceAll("[REDACTED]");
        redacted = CREDENTIAL.matcher(redacted).replaceAll("$1$2[REDACTED]");
        return redacted.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
