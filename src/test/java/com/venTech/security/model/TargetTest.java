package com.venTech.security.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TargetTest {

    @Test
    void extractsHostFromUrlWithExplicitPort() {
        Target target = new Target("app", "https://pp-dev.veportal.in:54514/login", ".", null, null, null);

        assertThat(target.host()).isEqualTo("pp-dev.veportal.in");
    }

    @Test
    void doesNotTreatDigitsAppendedToHostnameAsPort() {
        Target target = new Target("app", "https://pp-dev.veportal.in54514/login", ".", null, null, null);

        assertThat(target.host()).isEqualTo("pp-dev.veportal.in54514");
    }

    @Test
    void returnsNullWhenUrlHasNoParsableHost() {
        Target target = new Target("app", "https://pp-dev.veportal.in:invalid/login", ".", null, null, null);

        assertThat(target.host()).isNull();
    }
}
