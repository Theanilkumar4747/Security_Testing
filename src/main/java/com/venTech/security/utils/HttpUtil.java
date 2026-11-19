package com.venTech.security.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Minimal JDK HttpClient helper shared by the integrations and API-based scanners. */
public final class HttpUtil {
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NORMAL).build();

    public record Response(int status, String body, Map<String, List<String>> headers) {
        public String header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .map(e -> e.getValue().get(0)).findFirst().orElse(null);
        }
    }

    private HttpUtil() {}

    public static Response request(String method, String url, Map<String, String> headers, String body, Duration timeout)
            throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(timeout);
        if (headers != null) headers.forEach(b::header);
        b.method(method, body == null ? BodyPublishers.noBody() : BodyPublishers.ofString(body));
        return send(b.build());
    }

    public static Response get(String url, Map<String, String> headers) throws IOException, InterruptedException {
        return request("GET", url, headers, null, Duration.ofSeconds(60));
    }

    public static Response postJson(String url, Map<String, String> headers, String json) throws IOException, InterruptedException {
        java.util.Map<String, String> h = new java.util.HashMap<>(headers == null ? Map.of() : headers);
        h.put("Content-Type", "application/json");
        return request("POST", url, h, json, Duration.ofSeconds(60));
    }

    public static Response postMultipart(String url, Map<String, String> headers, Map<String, String> fields,
                                         String fileField, Path file, String fileContentType)
            throws IOException, InterruptedException {
        String boundary = "----sec" + UUID.randomUUID();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<String, String> f : fields.entrySet()) {
            out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + f.getKey() + "\"\r\n\r\n"
                    + f.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
        }
        out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fileField + "\"; filename=\""
                + file.getFileName() + "\"\r\nContent-Type: " + fileContentType + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(Files.readAllBytes(file));
        out.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(5))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(BodyPublishers.ofByteArray(out.toByteArray()));
        if (headers != null) headers.forEach(b::header);
        return send(b.build());
    }

    public static String basicAuth(String user, String pass) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
    }

    private static Response send(HttpRequest req) throws IOException, InterruptedException {
        HttpResponse<String> r = CLIENT.send(req, BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers().map());
    }
}
