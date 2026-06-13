package com.ticketti.api_gateway.filter;

import java.util.Set;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ticketti.api_gateway.config.JwtService;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Filtro global para autenticación JWT en el API Gateway. Intercepta todas las
 * peticiones y valida el token JWT antes de permitir el acceso.
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String HEADER_X_FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final String HEADER_X_REQUEST_ID = "X-Request-ID";

    private final JwtService jwtService;

    /**
     * Constructor con inyección de dependencia mediante Lombok.
     *
     * @param jwtService servicio para manejo de tokens JWT
     */
    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * Filtra las peticiones entrantes validando el token JWT. Las rutas
     * públicas (/auth/**) son excluidas de la validación.
     *
     * @param exchange el intercambio del servidor web
     * @param chain la cadena de filtros
     * @return Mono que completa el procesamiento de la petición
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String requestId = request.getHeaders().getFirst(HEADER_X_REQUEST_ID);

        if (esRutaPublica(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Falta o es invalido el header Authorization para la ruta: {}, requestId={}", path, requestId);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        if (!jwtService.validateToken(token)) {
            log.warn("Token JWT invalido o expirado para la ruta: {}, requestId={}", path, requestId);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String username = jwtService.extractUsername(token);
        Set<String> roles = jwtService.extractRoles(token);

        log.debug("Usuario autenticado: {}, roles: {}", username, roles);

        ServerHttpRequest.Builder builder = request.mutate()
                .header("X-Usuario", username)
                .header("X-Forwarded-For", request.getRemoteAddress() != null
                        ? request.getRemoteAddress().getAddress().getHostAddress() : "unknown")
            .header(HEADER_X_FORWARDED_PROTO, obtenerForwardedProto(request))
            .header(HEADER_X_REQUEST_ID, requestId != null && !requestId.isBlank() ? requestId : "unknown");

        if (roles != null && !roles.isEmpty()) {
            builder.header("X-Usuario-Rol", String.join(",", roles));
        }

        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    private static final Set<String> RUTAS_PUBLICAS = Set.of(
        // ═ Autenticación ═
        "/auth/**",
        "/api/v1/usuarios/validar-credenciales",  // Login interno BFF → API Gateway
        "/api/v1/usuarios",                       // Registro de usuario
        // ═ Eventos ═
        "/api/v1/eventos",                        // Listar eventos
        "/api/v1/eventos/**",                     // Detalle de evento
        "/api/v1/Eventos/**",                     // Compatibilidad case
        // ═ Carrito ═
        "/api/v1/Carrito/**",                     // Carrito (case original)
        "/api/v1/carrito/**",                     // Carrito (lowercase)
        // ═ Donaciones / Causas públicas ═
        "/api/v1/causas/activas",                 // Causas activas públicas
        "/api/v1/organizaciones/activas",         // Organizaciones activas públicas
        // ═ Notificaciones ═
        "/api/v1/notificaciones/**"               // Notificaciones (BFF valida JWT)
    );

    /**
     * Verifica si la ruta es pública y no requiere autenticación.
     *
     * @param path la ruta solicitada
     * @return true si la ruta es pública, false en caso contrario
     */
    private boolean esRutaPublica(String path) {
        return RUTAS_PUBLICAS.stream().anyMatch(patron -> coincideRuta(path, patron));
    }

    /**
     * Comprueba si la ruta coincide con el patrón especificado. Soporta
     * patrones con /** al final para coincidencia por prefijo.
     *
     * @param path la ruta a comparar
     * @param patron el patrón de ruta (ej: /auth/**)
     * @return true si coinciden, false en caso contrario
     */
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

    /**
     * Obtiene el protocolo de la petición considerando el encabezado X-Forwarded-Proto.
     *
     * @param request solicitud HTTP original
     * @return protocolo (http o https) desde el header o el esquema de la URI
     */
    private String obtenerForwardedProto(ServerHttpRequest request) {
        String forwardedProto = request.getHeaders().getFirst(HEADER_X_FORWARDED_PROTO);
        if (forwardedProto != null && !forwardedProto.isBlank()) {
            return forwardedProto;
        }

        String scheme = request.getURI().getScheme();
        return scheme != null && !scheme.isBlank() ? scheme : "http";
    }

    /**
     * Define el orden de ejecución del filtro. Se ejecuta con la máxima
     * prioridad para validar antes que otros filtros.
     *
     * @return el orden de prioridad del filtro
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}