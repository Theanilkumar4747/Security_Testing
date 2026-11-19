package com.venTech.security.core;

/** Contract implemented by every scanner plugin. */
public interface ScannerInterface {

    enum Category { SAST, SCA, DAST, API, SECRETS, CLOUD }

    /** Unique, lower-case scanner id (matches the key in scanners-config.yaml). */
    String name();

    Category category();

    /** True when the required binary / service is available on this machine. */
    boolean isAvailable();

    /** Runs the scan. Implementations must never throw; failures are reported in the result. */
    ScanResult scan(ScanConfig config);
}
