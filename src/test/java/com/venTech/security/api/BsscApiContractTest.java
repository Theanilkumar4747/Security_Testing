package com.venTech.security.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.restassured.response.Response;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Contract/regression checks against a local fixture; no requests are sent to the BSSC service. */
class BsscApiContractTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static HttpServer server;
    private static String baseUrl;

    @BeforeAll
    static void startFixture() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", BsscApiContractTest::respond);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopFixture() {
        if (server != null) server.stop(0);
    }

    @Test
    void capturedEndpointInventoryReturnsExpectedStatusesAndJson() throws Exception {
        List<BsscApiEndpoint> endpoints = BsscApiEndpoint.inventory();
        assertThat(endpoints).hasSize(13);

        for (BsscApiEndpoint endpoint : endpoints) {
            Response response = io.restassured.RestAssured.given()
                    .baseUri(baseUrl)
                    .when()
                    .request(endpoint.method(), endpoint.path());

            assertThat(response.statusCode())
                    .as("%s %s", endpoint.method(), endpoint.path())
                    .isEqualTo(endpoint.capturedStatus());
            assertThat(response.contentType()).contains("application/json");
            JsonNode json = MAPPER.readTree(response.asString());
            if (endpoint.capturedStatus() == 422) {
                assertThat(json.path("message").asText()).isEqualTo("validation error");
            } else {
                assertThat(json.path("status").asText()).isEqualTo("ok");
            }
        }
    }

    @Test
    void unknownEndpointReturnsNotFound() {
        Response response = io.restassured.RestAssured.given()
                .baseUri(baseUrl)
                .when()
                .get("/api/v1/not-in-capture");

        assertThat(response.statusCode()).isEqualTo(404);
    }

    private static void respond(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        BsscApiEndpoint endpoint = BsscApiEndpoint.inventory().stream()
                .filter(item -> item.path().equals(path))
                .findFirst()
                .orElse(null);

        int status;
        String body;
        if (endpoint == null) {
            status = 404;
            body = "{\"message\":\"not found\"}";
        } else if (!endpoint.method().equals(exchange.getRequestMethod())) {
            status = 405;
            body = "{\"message\":\"method not allowed\"}";
        } else if (endpoint.capturedStatus() == 422) {
            status = 422;
            body = "{\"message\":\"validation error\"}";
        } else {
            status = endpoint.capturedStatus();
            body = "{\"status\":\"ok\"}";
        }
        byte[] response = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, response.length);
        try (var output = exchange.getResponseBody()) {
            output.write(response);
        }
    }
}
