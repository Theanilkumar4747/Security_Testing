package com.venTech.security.utils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Runs external processes with a hard timeout. Output goes to temp files, so large output cannot deadlock. */
public final class CommandExecutor {
    private static final Logger LOG = Logger.get(CommandExecutor.class);

    public record Result(int exitCode, String stdout, String stderr) {}

    private CommandExecutor() {}

    public static Result run(List<String> cmd, Path workDir, Duration timeout, Map<String, String> env)
            throws IOException, InterruptedException, TimeoutException {
        Path out = Files.createTempFile("sec-out", ".log");
        Path err = Files.createTempFile("sec-err", ".log");
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectOutput(out.toFile()).redirectError(err.toFile());
            if (workDir != null) pb.directory(workDir.toFile());
            if (env != null) pb.environment().putAll(env);
            LOG.info("Executing: {} (+{} args)", cmd.get(0), cmd.size() - 1);
            Process p = pb.start();
            if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                p.descendants().forEach(ProcessHandle::destroyForcibly);
                p.destroyForcibly();
                throw new TimeoutException(cmd.get(0) + " exceeded " + timeout.toMinutes() + " min");
            }
            return new Result(p.exitValue(), read(out), read(err));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(err);
        }
    }

    /** True if the binary is an executable on PATH (or an existing executable path). */
    public static boolean exists(String binary) {
        File direct = new File(binary);
        if (direct.isAbsolute() || binary.contains(File.separator)) return direct.canExecute();
        String path = System.getenv("PATH");
        if (path == null) return false;
        String[] exts = System.getProperty("os.name", "").toLowerCase().contains("win")
                ? new String[]{"", ".exe", ".cmd", ".bat"} : new String[]{""};
        for (String dir : path.split(File.pathSeparator)) {
            for (String ext : exts) {
                if (new File(dir, binary + ext).canExecute()) return true;
            }
        }
        return false;
    }

    private static String read(Path p) throws IOException {
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }
}
