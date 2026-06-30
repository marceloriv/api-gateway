package com.ticketti.api_gateway;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

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

    private String tokenValido;

    @BeforeEach
    void setUp() {
        this.webTestClient = WebTestClient.bindToServer()
            .baseUrl("http://localhost:" + port)
            .build();

        SecretKey key = Keys.hmacShaKeyFor(
            "test-secret-for-testing-minimum-32-characters".getBytes(StandardCharsets.UTF_8));
        this.tokenValido = Jwts.builder()
            .subject("test@ticketti.com")
            .claim("rol", "CLIENTE")
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + 3600_000))
            .signWith(key)
            .compact();
    }

    @Test
    void fallbackEndpoint_retorna503() {
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
    void fallbackEndpoint_paraEventos_retorna503() {
        webTestClient.get()
            .uri("/fallback/eventos")
            .header("X-Request-ID", "req-456")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectBody()
            .jsonPath("$.service").isEqualTo("eventos")
            .jsonPath("$.message").isEqualTo("El servicio de eventos no está disponible. Intente más tarde.");
    }

    @Test
    void fallbackEndpoint_paraUsuarios_retorna503() {
        webTestClient.get()
            .uri("/fallback/usuarios")
            .header("X-Request-ID", "req-789")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectBody()
            .jsonPath("$.service").isEqualTo("usuarios")
            .jsonPath("$.message").isEqualTo("El servicio de usuarios no está disponible. Intente más tarde.");
    }

    @Test
    void rutaProtegida_sinToken_retorna401() {
        webTestClient.get()
            .uri("/api/v1/usuarios/1")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    void rutaPublica_sinToken_noRetorna401() {
        webTestClient.get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().value(status -> {
                org.assertj.core.api.Assertions.assertThat(status)
                    .as("Health endpoint debe retornar 200 (UP) o 503 (DOWN)")
                    .isIn(200, 503);
            });
    }

    @Test
    void rutaPublica_eventosGET_sinToken_noRetorna401() {
        webTestClient.get()
            .uri("/api/v1/eventos/listarEventos")
            .exchange()
            .expectStatus().value(status ->
                org.assertj.core.api.Assertions.assertThat(status)
                    .isNotEqualTo(401));
    }

    @Test
    void rutaProtegida_conTokenValido_noRetorna401() {
        webTestClient.get()
            .uri("/api/v1/usuarios/1")
            .header("Authorization", "Bearer " + tokenValido)
            .exchange()
            .expectStatus().value(status ->
                org.assertj.core.api.Assertions.assertThat(status)
                    .isNotEqualTo(401));
    }

    @Test
    void fallbackEndpoint_post_conBody_retorna503() {
        webTestClient.post()
            .uri("/fallback/donaciones")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"id\":123}")
            .header("X-Request-ID", "req-post-1")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectBody()
            .jsonPath("$.service").isEqualTo("donaciones")
            .jsonPath("$.message").isEqualTo("El servicio de donaciones no está disponible. Intente más tarde.");
    }

    @Test
    void fallbackEndpoint_servicioDesconocido_usaMensajeGenerico() {
        webTestClient.get()
            .uri("/fallback/pagos")
            .header("X-Request-ID", "req-default-1")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectBody()
            .jsonPath("$.service").isEqualTo("pagos")
            .jsonPath("$.message").isEqualTo("El servicio no está disponible temporalmente. Intente más tarde.");
    }
}
