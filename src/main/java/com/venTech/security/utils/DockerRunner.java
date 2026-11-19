package com.venTech.security.utils;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;

/** Runs tools from container images (ZAP, etc.) so they need no local install. */
public final class DockerRunner {
    private static final Logger LOG = Logger.get(DockerRunner.class);

    private DockerRunner() {}

    public static boolean isAvailable() { return CommandExecutor.exists("docker"); }

    /**
     * @param mounts    host path -> container path (mounted read-write)
     * @param env       variable names forwarded to the container (values passed via process env, not argv)
     * @param dockerOpts extra `docker run` options, e.g. "--network", "host"
     */
    public static CommandExecutor.Result run(String image, List<String> args, Map<String, Path> mounts,
                                             Map<String, String> env, List<String> dockerOpts, Duration timeout)
            throws Exception {
        String name = "sec-" + UUID.randomUUID().toString().substring(0, 8);
        List<String> cmd = new ArrayList<>(List.of("docker", "run", "--rm", "--name", name));
        if (dockerOpts != null) cmd.addAll(dockerOpts);
        if (mounts != null) mounts.forEach((container, host) -> {
            cmd.add("-v");
            cmd.add(host.toAbsolutePath() + ":" + container);
        });
        Map<String, String> procEnv = new HashMap<>();
        if (env != null) env.forEach((k, v) -> { cmd.add("-e"); cmd.add(k); procEnv.put(k, v); });
        cmd.add(image);
        if (args != null) cmd.addAll(args);
        try {
            return CommandExecutor.run(cmd, null, timeout, procEnv);
        } catch (TimeoutException e) {
            LOG.warn("Container {} timed out; removing", name);
            try { CommandExecutor.run(List.of("docker", "rm", "-f", name), null, Duration.ofSeconds(30), null); }
            catch (Exception ignored) { /* best effort */ }
            throw e;
        }
    }
}
