package com.company.security.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class FileUtils {
    private FileUtils() {}

    public static String readString(Path p) throws IOException {
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    public static void writeString(Path p, String content) throws IOException {
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.write(p, content.getBytes(StandardCharsets.UTF_8));
    }

    public static String readResource(String resource) throws IOException {
        try (InputStream in = FileUtils.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Classpath resource not found: " + resource);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Copies a classpath resource to dir/<filename> so external tools (semgrep, zap...) can read it. */
    public static Path extractResource(String resource, Path dir) throws IOException {
        Files.createDirectories(dir);
        Path target = dir.resolve(Path.of(resource).getFileName().toString());
        try (InputStream in = FileUtils.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) throw new IOException("Classpath resource not found: " + resource);
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return target;
    }

    public static void copy(Path src, Path dst) throws IOException {
        if (dst.getParent() != null) Files.createDirectories(dst.getParent());
        Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
    }
}
