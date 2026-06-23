package com.ticketti.api_gateway.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    private String validToken;
    private String expiredToken;
    private String invalidToken;

    @BeforeEach
    void configurar() {
        String secretKey = "ticketti-secret-key-2024-for-jwt-signing-and-verification-only";
        ReflectionTestUtils.setField(jwtService, "secretKey", secretKey);

        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        validToken = Jwts.builder()
                .subject("testuser@example.com")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .claim("rol", "ADMINPLATAFORMA")
                .claim("usuarioId", 42)
                .signWith(key)
                .compact();

        expiredToken = Jwts.builder()
                .subject("testuser@example.com")
                .issuedAt(new Date(System.currentTimeMillis() - 7200000))
                .expiration(new Date(System.currentTimeMillis() - 3600000))
                .claim("rol", "CLIENTE")
                .signWith(key)
                .compact();

        invalidToken = "invalid.token.here";
    }

    @Test
    void extraerNombreUsuario_TokenValido_RetornaNombreUsuario() {
        String username = jwtService.extractUsername(validToken);
        assertEquals("testuser@example.com", username);
    }

    @Test
    void extraerNombreUsuario_TokenInvalido_LanzaExcepcion() {
        assertThrows(Exception.class, () -> jwtService.extractUsername(invalidToken));
    }

    @Test
    void extraerExpiracion_TokenValido_RetornaFechaExpiracion() {
        Date expiration = jwtService.extractExpiration(validToken);
        assertNotNull(expiration);
        assertTrue(expiration.after(new Date()));
    }

    @Test
    void extraerClaim_TokenValido_RetornaClaim() {
        String subject = jwtService.extractClaim(validToken, claims -> claims.getSubject());
        assertEquals("testuser@example.com", subject);
    }

    @Test
    void validarToken_TokenValido_RetornaVerdadero() {
        Boolean isValid = jwtService.validateToken(validToken);
        assertTrue(isValid);
    }

    @Test
    void validarToken_TokenExpirado_RetornaFalso() {
        Boolean isValid = jwtService.validateToken(expiredToken);
        assertFalse(isValid);
    }

    @Test
    void validarToken_TokenInvalido_RetornaFalso() {
        Boolean isValid = jwtService.validateToken(invalidToken);
        assertFalse(isValid);
    }

    @Test
    void extraerRoles_TokenValido_RetornaRoles() {
        Set<String> roles = jwtService.extractRol(validToken);
        assertNotNull(roles);
        assertTrue(roles.contains("ADMINPLATAFORMA"));
    }

    @Test
    void extraerRoles_TokenSinRoles_RetornaConjuntoVacio() {
        String secretKey = "ticketti-secret-key-2024-for-jwt-signing-and-verification-only";
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        String tokenWithoutRoles = Jwts.builder()
                .subject("testuser@example.com")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key)
                .compact();

        Set<String> roles = jwtService.extractRol(tokenWithoutRoles);
        assertNull(roles);
    }

    @Test
    void extraerUsuarioId_TokenValido_RetornaId() {
        Long id = jwtService.extractUsuarioId(validToken);
        assertNotNull(id);
        assertEquals(42L, id);
    }
}
