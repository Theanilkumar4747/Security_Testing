package com.company.security.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TargetTest {

    @Test
    void extractsHostFromUrlWithExplicitPort() {
        Target target = new Target("app", "https://example.com:54514/login", ".", null, null, null);

        assertThat(target.host()).isEqualTo("example.com");
    }

    @Test
    void doesNotTreatDigitsAppendedToHostnameAsPort() {
        Target target = new Target("app", "https://example.com54514/login", ".", null, null, null);

        assertThat(target.host()).isEqualTo("example.com54514");
    }

    @Test
    void returnsNullWhenUrlHasNoParsableHost() {
        Target target = new Target("app", "https://example.com:invalid/login", ".", null, null, null);

        assertThat(target.host()).isNull();
    }
}
