package com.venTech.security.core;

/** Normalised severity used across all scanners. */
public enum Severity {
    INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    private final int weight;

    Severity(int weight) { this.weight = weight; }

    public int weight() { return weight; }

    public boolean atLeast(Severity other) { return weight >= other.weight; }

    /** Maps the many vendor severity vocabularies onto the five-level scale. */
    public static Severity fromString(String s) {
        if (s == null) return INFO;
        return switch (s.trim().toUpperCase()) {
            case "CRITICAL", "BLOCKER" -> CRITICAL;
            case "HIGH", "ERROR", "IMPORTANT" -> HIGH;
            case "MEDIUM", "MODERATE", "WARNING" -> MEDIUM;
            case "LOW", "MINOR" -> LOW;
            default -> INFO;
        };
    }
}
