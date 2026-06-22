package com.ticketti.api_gateway.config;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtService {

    /**
     * Clave secreta utilizada para firmar y verificar tokens JWT.
     * Se configura mediante la propiedad {@code jwt.secret}.
     */
    @Value("${jwt.secret:clave-secreta-super-larga-de-minimo-32-caracteres}")
    private String secretKey;

    /**
     * Emisor esperado (iss) en los tokens JWT.
     * Se configura mediante la propiedad {@code jwt.issuer}.
     * Si está vacío, no se valida.
     */
    @Value("${jwt.issuer:}")
    private String issuer;

    /**
     * Audiencia esperada (aud) en los tokens JWT.
     * Se configura mediante la propiedad {@code jwt.audience}.
     * Si está vacío, no se valida.
     */
    @Value("${jwt.audience:}")
    private String audience;

    /**
     * Obtiene la clave de firma utilizada para verificar tokens JWT.
     * La clave se deriva del secreto configurado en {@code jwt.secret}.
     *
     * @return clave de firma HMAC
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Extrae el nombre de usuario (subject) del token JWT.
     *
     * @param token token JWT válido
     * @return nombre de usuario (subject)
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración del token JWT.
     *
     * @param token token JWT válido
     * @return fecha de expiración
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrae un claim específico del token JWT usando una función resolución.
     *
     * @param token token JWT válido
     * @param claimsResolver función para resolver el claim deseado
     * @param <T> tipo del claim a resolver
     * @return valor del claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los claims del token JWT después de verificar la firma.
     *
     * @param token token JWT a parsear
     * @return objeto Claims con toda la información del token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifica si el token JWT está expirado.
     *
     * @param token token JWT a verificar
     * @return true si el token está expirado, false en caso contrario
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Valida un token JWT verificando su firma, expiración, emisor y audiencia.
     * La validación de emisor y audiencia se realiza solo si están configuradas
     * las propiedades correspondientes.
     *
     * @param token token JWT a validar
     * @return true si el token es válido, false en caso contrario
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (isTokenExpired(token)) {
                return false;
            }
            return isValidIssuer(claims) && isValidAudience(claims);
        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Valida que el claim issuer (iss) del token coincida con el configurado.
     *
     * @param claims claims extraídos del token JWT
     * @return true si el issuer es válido o no está configurado
     */
    private boolean isValidIssuer(Claims claims) {
        if (issuer == null || issuer.isEmpty()) {
            return true;
        }

        return issuer.equals(claims.getIssuer());
    }

    /**
     * Valida que el claim audience (aud) del token contenga el valor configurado.
     * Soporta tanto un String simple como un conjunto de valores.
     *
     * @param claims claims extraídos del token JWT
     * @return true si la audiencia es válida o no está configurada
     */
    private boolean isValidAudience(Claims claims) {
        if (audience == null || audience.isEmpty()) {
            return true;
        }

        Object tokenAudience = claims.get("aud");
        if (tokenAudience instanceof String audienceValue) {
            return audience.equals(audienceValue);
        }
        if (tokenAudience instanceof Set<?> audienceValues) {
            return audienceValues.contains(audience);
        }

        return false;
    }

    /**
     * Extrae el rol (claim "rol") del token JWT.
     * Compatible con tokens emitidos por el BFF que usan un solo rol por usuario.
     *
     * @param token token JWT válido
     * @return conjunto con el rol incluido en el token, o null si no existe
     */
    public Set<String> extractRol(String token) {
        Claims claims = extractAllClaims(token);
        String rol = claims.get("rol", String.class);
        if (rol != null && !rol.isBlank()) {
            return Set.of(rol.trim().toUpperCase());
        }
        return null;
    }

    /**
     * Extrae el ID de usuario (claim "usuarioId") del token JWT.
     *
     * @param token token JWT válido
     * @return ID de usuario numérico, o null si no existe
     */
    public Long extractUsuarioId(String token) {
        Claims claims = extractAllClaims(token);
        Object id = claims.get("usuarioId");
        if (id instanceof Number n) return n.longValue();
        return null;
    }
}
