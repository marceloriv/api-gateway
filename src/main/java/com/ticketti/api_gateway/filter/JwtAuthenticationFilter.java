package com.ticketti.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Filtro global que agrega headers de infraestructura (X-Forwarded-For, etc.)
 * a las peticiones que pasan por el Gateway.
 * La validación JWT y el populate del ReactiveSecurityContext se realizan
 * en JwtAuthenticationWebFilter (WebFilter), que ejecuta ANTES de este filtro.
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String HEADER_X_FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final String HEADER_X_REQUEST_ID = "X-Request-ID";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String requestId = request.getHeaders().getFirst(HEADER_X_REQUEST_ID);

        ServerHttpRequest.Builder builder = request.mutate()
                .header("X-Forwarded-For", request.getRemoteAddress() != null
                        ? request.getRemoteAddress().getAddress().getHostAddress() : "unknown")
                .header(HEADER_X_FORWARDED_PROTO, obtenerForwardedProto(request))
                .header(HEADER_X_REQUEST_ID, requestId != null && !requestId.isBlank() ? requestId : "unknown");

        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    private String obtenerForwardedProto(ServerHttpRequest request) {
        String forwardedProto = request.getHeaders().getFirst(HEADER_X_FORWARDED_PROTO);
        if (forwardedProto != null && !forwardedProto.isBlank()) {
            return forwardedProto;
        }
        String scheme = request.getURI().getScheme();
        return scheme != null && !scheme.isBlank() ? scheme : "http";
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}