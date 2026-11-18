package com.company.security.gate;

import com.company.security.utils.Logger;

/** Turns a gate verdict into a process exit code so CI (GitHub Actions, Jenkins) fails the build. */
public final class BuildBreaker {
    private static final Logger LOG = Logger.get(BuildBreaker.class);

    private BuildBreaker() {}

    public static int exitCode(QualityGate.GateResult result) { return result.passed() ? 0 : 1; }

    public static void log(QualityGate.GateResult result) {
        if (result.passed()) {
            LOG.info("QUALITY GATE PASSED ({} finding(s) suppressed)", result.suppressed());
        } else {
            LOG.error("QUALITY GATE FAILED:");
            result.violations().forEach(v -> LOG.error(" - {}", v));
        }
    }

    /** Convenience for callers that want to stop the JVM immediately. */
    public static void enforce(QualityGate.GateResult result) {
        log(result);
        if (!result.passed()) System.exit(1);
    }
}
