package com.ticketti.api_gateway.filter;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.ticketti.api_gateway.config.JwtService;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * WebFilter para autenticacion JWT en el API Gateway.
 * Se ejecuta ANTES de Spring Security's AuthorizationWebFilter,
 * validando el token JWT y poblando el ReactiveSecurityContext
 * con el Authentication necesario para que .anyExchange().authenticated() funcione.
 */
@Slf4j
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private static final String HEADER_X_FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final String HEADER_X_REQUEST_ID = "X-Request-ID";

    private final JwtService jwtService;

    public JwtAuthenticationWebFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String requestId = request.getHeaders().getFirst(HEADER_X_REQUEST_ID);

        if (esRutaPublica(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("Falta header Authorization para ruta: {}, requestId={}", path, requestId);
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        if (!jwtService.validateToken(token)) {
            log.warn("Token JWT invalido o expirado para la ruta: {}, requestId={}", path, requestId);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String username = jwtService.extractUsername(token);
        Set<String> roles = jwtService.extractRol(token);
        Long usuarioId = jwtService.extractUsuarioId(token);

        log.debug("Usuario autenticado: {}, roles: {}, usuarioId: {}", username, roles, usuarioId);

        if (roles == null || roles.isEmpty()) {
            log.warn("Token sin roles para la ruta: {}, requestId={}", path, requestId);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        if (coincideConRutaProtegida(path, RUTAS_ORGANIZADOR)) {
            if (!roles.contains("ORGANIZADOR") && !roles.contains("ADMINPLATAFORMA")) {
                log.warn("Acceso denegado: usuario {} no tiene rol ORGANIZADOR/ADMIN para ruta: {}, requestId={}",
                        username, path, requestId);
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }

        if (coincideConRutaProtegida(path, RUTAS_ADMIN)) {
            if (!roles.contains("ADMINPLATAFORMA")) {
                log.warn("Acceso denegado: usuario {} no tiene rol ADMINPLATAFORMA para ruta: {}, requestId={}",
                        username, path, requestId);
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol))
                .toList();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, token, authorities);

        ServerHttpRequest.Builder builder = request.mutate()
                .header("X-Usuario", username)
                .header("X-Forwarded-For", request.getRemoteAddress() != null
                        ? request.getRemoteAddress().getAddress().getHostAddress() : "unknown")
                .header(HEADER_X_FORWARDED_PROTO, obtenerForwardedProto(request))
                .header(HEADER_X_REQUEST_ID, requestId != null && !requestId.isBlank() ? requestId : "unknown");

        if (usuarioId != null) {
            builder.header("X-Usuario-Id", String.valueOf(usuarioId));
        }
        if (roles != null && !roles.isEmpty()) {
            builder.header("X-Rol-Usuario-Id", String.join(",", roles));
        }

        ServerWebExchange mutatedExchange = exchange.mutate().request(builder.build()).build();

        return chain.filter(mutatedExchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
    }

    private static final Set<String> RUTAS_PUBLICAS = Set.of(
        "/auth/**",
        "/api/v1/usuarios/validar-credenciales",
        "/api/v1/usuarios",
        "/api/v1/eventos",
        "/api/v1/eventos/listarEventos",
        "/api/v1/eventos/buscarEvento/**",
        "/api/v1/Eventos/**",
        "/api/v0/Eventos/**",
        "/api/v1/Carrito/crear",
        "/api/v1/carrito/crear",
        "/api/v1/causas/activas",
        "/api/v1/organizaciones",
        "/api/v1/organizaciones/todas",
        "/actuator/health",
        "/actuator/info"
    );

    private static final Set<String> RUTAS_ORGANIZADOR = Set.of(
        "/api/v1/eventos/crear",
        "/api/v1/eventos/mis"
    );

    private static final Set<String> RUTAS_ADMIN = Set.of(
        "/api/v1/donaciones/"
    );

    private boolean esRutaPublica(String path) {
        return RUTAS_PUBLICAS.stream().anyMatch(patron -> coincideRuta(path, patron));
    }

    private boolean coincideConRutaProtegida(String path, Set<String> rutas) {
        return rutas.stream().anyMatch(patron -> coincideRuta(path, patron));
    }

    private boolean coincideRuta(String path, String patron) {
        if (patron.equals("/**")) {
            return true;
        }
        if (patron.endsWith("/**")) {
            String prefijo = patron.substring(0, patron.length() - 3);
            return path.startsWith(prefijo);
        }
        return path.equals(patron);
    }

    private String obtenerForwardedProto(ServerHttpRequest request) {
        String forwardedProto = request.getHeaders().getFirst(HEADER_X_FORWARDED_PROTO);
        if (forwardedProto != null && !forwardedProto.isBlank()) {
            return forwardedProto;
        }
        String scheme = request.getURI().getScheme();
        return scheme != null && !scheme.isBlank() ? scheme : "http";
    }
}
