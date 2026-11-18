package com.company.security.core;

import com.company.security.model.Target;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Per-scanner run configuration. */
public record ScanConfig(Target target, Path outputDir, Duration timeout, Map<String, String> options) {

    public ScanConfig {
        options = options == null ? Map.of() : Map.copyOf(options);
        if (timeout == null) timeout = Duration.ofMinutes(15);
    }

    public String option(String key, String def) {
        String v = options.get(key);
        return v == null || v.isBlank() ? def : v;
    }

    public int intOption(String key, int def) {
        try { return Integer.parseInt(option(key, String.valueOf(def))); }
        catch (NumberFormatException e) { return def; }
    }

    public List<String> listOption(String key, String def) {
        return Arrays.stream(option(key, def == null ? "" : def).split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
