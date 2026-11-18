package com.company.security.model;

import java.net.URI;
import java.util.Locale;

/** What is being scanned: a running app, a source tree, a container image, IaC and/or an OpenAPI spec. */
public record Target(String name, String url, String sourcePath, String imageName, String openApiSpec, String iacPath) {

    public String host() {
        if (url == null || url.isBlank()) return null;
        try {
            URI parsed = URI.create(url.trim());
            String host = parsed.getHost();
            return host == null || host.isBlank() ? null : host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
