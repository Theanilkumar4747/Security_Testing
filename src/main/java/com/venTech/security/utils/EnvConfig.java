package com.venTech.security.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Configuration lookup. Precedence: JVM -Dkey, environment variable (KEY_NAME), external file
 * ($SECURITY_CONFIG_FILE), classpath config/application.properties.
 * Secrets (tokens, passwords) should only ever come from the environment.
 */
public final class EnvConfig {
    private static final Properties PROPS = new Properties();

    static {
        try (InputStream in = EnvConfig.class.getClassLoader().getResourceAsStream("config/application.properties")) {
            if (in != null) PROPS.load(in);
            String ext = System.getenv("SECURITY_CONFIG_FILE");
            if (ext != null && !ext.isBlank()) {
                try (InputStream f = Files.newInputStream(Path.of(ext))) { PROPS.load(f); }
            }
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private EnvConfig() {}

    public static String get(String key, String def) {
        String sys = System.getProperty(key);
        if (sys != null) return sys;
        String env = System.getenv(toEnvName(key));
        if (env != null && !env.isBlank()) return env;
        return PROPS.getProperty(key, def);
    }

    public static String get(String key) { 
        return get(key, null);
         }

    public static String require(String key) {
        String v = get(key, null);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Missing required setting '" + key + "' (env " + toEnvName(key) + ")");
        }
        return v;
    }

    public static int getInt(String key, int def) {
        try { return Integer.parseInt(get(key, String.valueOf(def)).trim()); }
        catch (NumberFormatException e) { return def; }
    }

    public static boolean getBool(String key, boolean def) {
        return Boolean.parseBoolean(get(key, String.valueOf(def)).trim());
    }

    public static List<String> getList(String key) {
        String v = get(key, "");
        return Arrays.stream(v.split("[;,\\s]+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    static String toEnvName(String key) {
        return key.toUpperCase().replace('.', '_').replace('-', '_');
    }
}
