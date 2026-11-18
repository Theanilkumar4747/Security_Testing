package com.company.security.core;

import com.company.security.model.Vulnerability;
import com.company.security.utils.CommandExecutor;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import com.company.security.utils.Logger;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Template-method base class: availability check, authorisation guard, timing and
 * error handling live here so concrete scanners only implement execute() and parse().
 */
public abstract class BaseScanner implements ScannerInterface {

    protected final Logger log = Logger.get(getClass());
    protected static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /** Runs the tool and returns its raw (JSON/XML/text) output. */
    protected abstract String execute(ScanConfig config) throws Exception;

    /** Converts raw tool output into normalised vulnerabilities. */
    public abstract List<Vulnerability> parse(String raw) throws Exception;

    /** Executable that must be on PATH, or null if none is required. */
    protected String requiredBinary() { return null; }

    @Override
    public boolean isAvailable() {
        String bin = requiredBinary();
        return bin == null || CommandExecutor.exists(bin);
    }

    @Override
    public final ScanResult scan(ScanConfig config) {
        long start = System.currentTimeMillis();
        try {
            if (!isAuthorized(config)) {
                log.warn("{} refused to scan an unauthorized target host '{}'", name(), config.target().host());
                return ScanResult.failed(name(), category(),
                        "Target not authorised: set scan.url and add its host to scan.allowed.hosts", 0);
            }
            if (!isAvailable()) {
                log.warn("{} skipped - required tool '{}' not found", name(), requiredBinary());
                return ScanResult.skipped(name(), category(), "Required tool not found: " + requiredBinary());
            }
            Files.createDirectories(config.outputDir());
            log.info("{} started", name());
            List<Vulnerability> vulns = parse(execute(config));
            long ms = System.currentTimeMillis() - start;
            log.info("{} finished in {} ms with {} findings", name(), ms, vulns.size());
            return ScanResult.success(name(), category(), vulns, ms);
        } catch (TimeoutException e) {
            log.error(name() + " timed out", e);
            return ScanResult.failed(name(), category(), "Timed out: " + e.getMessage(), System.currentTimeMillis() - start);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("{} interrupted", name());
            return ScanResult.failed(name(), category(), "Interrupted", System.currentTimeMillis() - start);
        } catch (Exception e) {
            log.error(name() + " failed", e);
            return ScanResult.failed(name(), category(), String.valueOf(e.getMessage()), System.currentTimeMillis() - start);
        }
    }

    /**
     * Safety guard: dynamic scanners (DAST/API) only touch hosts explicitly listed in
     * scan.allowed.hosts (supports "*.example.com").
     */
    protected boolean isAuthorized(ScanConfig config) {
        Category c = category();
        if (c != Category.DAST && c != Category.API) return true;
        String host = config.target().host();
        if (host == null || host.isBlank()) return false;

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        for (String allowed : EnvConfig.getList("scan.allowed.hosts")) {
            String candidate = allowed.trim();
            if (candidate.isEmpty()) continue;
            String normalizedCandidate = candidate.toLowerCase(Locale.ROOT);
            if (normalizedCandidate.equals(normalizedHost)) return true;
            if (normalizedCandidate.startsWith("*.")) {
                String suffix = normalizedCandidate.substring(1);
                if (normalizedHost.endsWith(suffix)) return true;
            }
            if (isLoopbackHost(normalizedHost) && isLoopbackHost(normalizedCandidate)) return true;
        }
        return false;
    }

    private static boolean isLoopbackHost(String host) {
        if (host == null || host.isBlank()) return false;
        if (host.equals("localhost") || host.equals("::1") || host.equals("127.0.0.1") || host.equals("0.0.0.0")) return true;
        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (address.isLoopbackAddress() || address.isAnyLocalAddress()) return true;
            }
        } catch (UnknownHostException ignored) {
            return false;
        }
        return false;
    }

    // ---------------------------------------------------------------- helpers

    protected CommandExecutor.Result run(ScanConfig cfg, List<String> cmd, Map<String, String> env, int... okCodes)
            throws IOException, InterruptedException, TimeoutException {
        CommandExecutor.Result r = CommandExecutor.run(cmd, null, cfg.timeout(), env);
        for (int ok : okCodes) if (r.exitCode() == ok) return r;
        throw new IOException(name() + " exited with code " + r.exitCode() + ": " + truncate(r.stderr(), 800));
    }

    protected static String sourcePath(ScanConfig c) {
        String p = c.target().sourcePath();
        return p == null || p.isBlank() ? "." : p;
    }

    /** Resolves "classpath:rules/x.yaml" to an extracted file; other values are returned as-is. */
    protected String resolveResource(ScanConfig cfg, String value) throws IOException {
        if (value != null && value.startsWith("classpath:")) {
            return FileUtils.extractResource(value.substring("classpath:".length()), cfg.outputDir()).toString();
        }
        return value;
    }

    protected static String text(JsonNode n, String field, String def) {
        JsonNode v = n.path(field);
        return v.isMissingNode() || v.isNull() ? def : v.asText(def);
    }

    protected static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    protected static String stripHtml(String s) {
        return s == null ? null : s.replaceAll("<[^>]+>", "").trim();
    }

    protected String toRaw(List<Vulnerability> vulns) throws IOException {
        return MAPPER.writeValueAsString(vulns);
    }

    protected List<Vulnerability> fromRaw(String raw) throws IOException {
        return MAPPER.readValue(raw, new TypeReference<List<Vulnerability>>() {});
    }

    protected static Path file(ScanConfig cfg, String name) { return cfg.outputDir().resolve(name); }
}
