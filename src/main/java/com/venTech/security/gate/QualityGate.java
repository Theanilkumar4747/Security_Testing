package com.venTech.security.gate;

import com.venTech.security.core.ScanResult;
import com.venTech.security.core.ScannerInterface.Category;
import com.venTech.security.core.Severity;
import com.venTech.security.model.ScanReport;
import com.venTech.security.model.Vulnerability;
import com.venTech.security.utils.EnvConfig;
import com.venTech.security.utils.FileUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Decides pass/fail from global and per-category thresholds, after applying unexpired suppressions. */
public class QualityGate {

    public record GateResult(boolean passed, List<String> violations, Map<Severity, Long> counts, int suppressed) {}

    private final ThresholdEvaluator global;
    private final Map<Category, ThresholdEvaluator> perCategory = new EnumMap<>(Category.class);
    private final boolean failOnScannerError;
    private final Map<String, LocalDate> suppressions = new HashMap<>(); // id/cve/fingerprint -> expiry (null = never)

    private QualityGate(JsonNode gate) {
        this.global = new ThresholdEvaluator(gate.path("maxAllowed"));
        gate.path("perCategory").fields().forEachRemaining(e ->
                perCategory.put(Category.valueOf(e.getKey().toUpperCase()), new ThresholdEvaluator(e.getValue())));
        this.failOnScannerError = gate.path("failOnScannerError").asBoolean(false);
        for (JsonNode s : gate.path("suppressions")) {
            String exp = s.path("expires").asText(null);
            suppressions.put(s.path("id").asText(), exp == null ? null : LocalDate.parse(exp));
        }
    }

    public static QualityGate load() throws IOException {
        String external = EnvConfig.get("gate.config");
        String yaml = external != null ? FileUtils.readString(Path.of(external)) : FileUtils.readResource("config/quality-gate.yaml");
        return fromYaml(yaml);
    }

    public static QualityGate fromYaml(String yaml) throws IOException {
        return new QualityGate(new YAMLMapper().readTree(yaml).path("gate"));
    }

    public GateResult evaluate(ScanReport report) {
        List<Vulnerability> all = new ArrayList<>(report.vulnerabilities());
        int before = all.size();
        all.removeIf(this::isSuppressed);
        List<String> violations = new ArrayList<>(global.evaluate("overall", all));

        perCategory.forEach((cat, evaluator) ->
                violations.addAll(evaluator.evaluate(cat.name(), all.stream().filter(v -> v.category() == cat).toList())));

        if (failOnScannerError) {
            for (ScanResult r : report.results()) {
                if (r.status() == ScanResult.Status.FAILED) violations.add("Scanner '" + r.scanner() + "' failed: " + r.message());
            }
        }
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) counts.put(s, all.stream().filter(v -> v.severity() == s).count());
        return new GateResult(violations.isEmpty(), violations, counts, before - all.size());
    }

    private boolean isSuppressed(Vulnerability v) {
        for (String key : new String[]{v.id(), v.cve(), v.fingerprint()}) {
            if (key != null && suppressions.containsKey(key)) {
                LocalDate expiry = suppressions.get(key);
                if (expiry == null || !expiry.isBefore(LocalDate.now())) return true;
            }
        }
        return false;
    }
}
