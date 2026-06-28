package com.ticketti.api_gateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.cloud.discovery.enabled=false",
        "spring.cloud.config.enabled=false",
        "eureka.client.enabled=false",
        "jwt.secret=test-secret-for-testing-minimum-32-characters"
    }
)
class ApiGatewayIntegrationTest {

    @LocalServerPort
    private int port;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        this.webTestClient = WebTestClient.bindToServer()
            .baseUrl("http://localhost:" + port)
            .build();
    }

    @Test
    void fallbackEndpointReturnsServiceUnavailable() {
        webTestClient.get()
            .uri("/fallback/auth")
            .header("X-Request-ID", "test-request-id-123")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectHeader().valueEquals("X-Request-ID", "test-request-id-123")
            .expectHeader().valueEquals("Retry-After", "30")
            .expectBody()
            .jsonPath("$.status").isEqualTo(503)
            .jsonPath("$.error").isEqualTo("Service Unavailable")
            .jsonPath("$.service").isEqualTo("auth")
            .jsonPath("$.message").isEqualTo("El servicio de autenticación no está disponible. Intente más tarde.")
            .jsonPath("$.requestId").isEqualTo("test-request-id-123");
    }

    @Test
    void actuatorHealthEndpointReturnsOkOrDown() {
        webTestClient.get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().value(status -> {
                org.assertj.core.api.Assertions.assertThat(status)
                    .as("El endpoint de health debe retornar 200 (UP) o 503 (DOWN)")
                    .isIn(200, 503);
            });
    }
}
