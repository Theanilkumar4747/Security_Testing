package com.venTech.security.model;

import com.venTech.security.core.ScanResult;
import com.venTech.security.core.Severity;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public record ScanReport(String id, Instant startedAt, Instant finishedAt, Target target, List<ScanResult> results) {

    public List<Vulnerability> vulnerabilities() {
        return results.stream().flatMap(r -> r.vulnerabilities().stream()).toList();
    }

    public Map<Severity, Long> countBySeverity() {
        Map<Severity, Long> m = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) m.put(s, 0L);
        vulnerabilities().forEach(v -> m.merge(v.severity(), 1L, Long::sum));
        return m;
    }
}
