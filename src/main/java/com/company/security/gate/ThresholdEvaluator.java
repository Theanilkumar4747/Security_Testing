package com.company.security.gate;

import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Compares finding counts per severity with allowed maximums (-1 = unlimited). */
public class ThresholdEvaluator {
    private final Map<Severity, Integer> limits = new EnumMap<>(Severity.class);

    public ThresholdEvaluator(JsonNode limitsNode) {
        if (limitsNode != null) {
            limitsNode.fields().forEachRemaining(e -> limits.put(Severity.valueOf(e.getKey().toUpperCase()), e.getValue().asInt(-1)));
        }
    }

    public List<String> evaluate(String scope, List<Vulnerability> vulns) {
        List<String> violations = new ArrayList<>();
        for (Map.Entry<Severity, Integer> e : limits.entrySet()) {
            if (e.getValue() < 0) continue;
            long count = vulns.stream().filter(v -> v.severity() == e.getKey()).count();
            if (count > e.getValue()) {
                violations.add(scope + ": " + count + " " + e.getKey() + " finding(s), maximum allowed is " + e.getValue());
            }
        }
        return violations;
    }
}
