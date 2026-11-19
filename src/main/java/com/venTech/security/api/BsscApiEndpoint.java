package com.venTech.security.api;

import java.util.List;

/** Endpoints observed in the supplied BSSC HAR capture. Statuses are capture baselines, not schema definitions. */
public record BsscApiEndpoint(String module, String method, String path, int capturedStatus) {
    private static final List<BsscApiEndpoint> INVENTORY = List.of(
            new BsscApiEndpoint("application", "GET", "/api/v1/application/steps/all", 200),
            new BsscApiEndpoint("authentication", "GET", "/api/v1/auth/captcha", 200),
            new BsscApiEndpoint("master-data", "GET", "/api/v1/categories", 200),
            new BsscApiEndpoint("master-data", "GET", "/api/v1/countries", 200),
            new BsscApiEndpoint("master-data", "GET", "/api/v1/countries/1/states", 200),
            new BsscApiEndpoint("master-data", "GET", "/api/v1/disabilities", 200),
            new BsscApiEndpoint("master-data", "GET", "/api/v1/states/4/districts", 200),
            new BsscApiEndpoint("application", "PATCH", "/api/v1/auth/candidate/step-1", 200),
            new BsscApiEndpoint("authentication", "POST", "/api/v1/auth/candidate/finalize", 200),
            new BsscApiEndpoint("authentication", "POST", "/api/v1/auth/candidate/initiate", 200),
            new BsscApiEndpoint("authentication", "POST", "/api/v1/auth/candidate/verify-otp", 200),
            new BsscApiEndpoint("authentication", "POST", "/api/v1/auth/captcha/validate", 200),
            new BsscApiEndpoint("payment", "POST", "/api/v1/payment/initiate", 422));

    public static List<BsscApiEndpoint> inventory() {
        return INVENTORY;
    }
}
