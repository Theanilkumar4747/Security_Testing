package com.venTech.security.core;

import com.venTech.security.core.ScannerInterface.Category;
import com.venTech.security.model.Vulnerability;
import java.util.List;

public record ScanResult(String scanner, Category category, Status status,
                         List<Vulnerability> vulnerabilities, long durationMs, String message) {

    public enum Status { SUCCESS, FAILED, SKIPPED }

    public ScanResult {
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
    }

    public static ScanResult success(String scanner, Category c, List<Vulnerability> v, long ms) {
        return new ScanResult(scanner, c, Status.SUCCESS, v, ms, null);
    }

    public static ScanResult failed(String scanner, Category c, String message, long ms) {
        return new ScanResult(scanner, c, Status.FAILED, List.of(), ms, message);
    }

    public static ScanResult skipped(String scanner, Category c, String message) {
        return new ScanResult(scanner, c, Status.SKIPPED, List.of(), 0, message);
    }
}
