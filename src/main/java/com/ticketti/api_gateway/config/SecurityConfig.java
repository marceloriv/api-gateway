package com.ticketti.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.ticketti.api_gateway.filter.JwtAuthenticationWebFilter;

/**
 * Configuración de seguridad de Spring Security para el API Gateway.
 * Define rutas públicas y protegidas, y deshabilita autenticación básica y formularios.
 * El JwtAuthenticationWebFilter se registra antes de AUTHORIZATION para que
 * el ReactiveSecurityContext tenga el Authentication antes del check .anyExchange().authenticated().
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtAuthenticationWebFilter jwtWebFilter;

    public SecurityConfig(JwtAuthenticationWebFilter jwtWebFilter) {
        this.jwtWebFilter = jwtWebFilter;
    }

    /**
     * Define la cadena de filtros de seguridad de Spring Security para el gateway.
     * Configura el acceso a rutas públicas y protege el resto con autenticación.
     *
     * @param http objeto de configuración de seguridad HTTP reactiva
     * @return cadena de filtros de seguridad configurada
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .addFilterBefore(jwtWebFilter, SecurityWebFiltersOrder.AUTHORIZATION)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/health", "/actuator/info").permitAll()
                        // ═ Autenticación ═
                        .pathMatchers("/auth/**").permitAll()
                        .pathMatchers("/api/v1/usuarios").permitAll()
                        .pathMatchers("/api/v1/usuarios/validar-credenciales").permitAll()
                        // ═ Eventos — solo lectura pública ═
                        .pathMatchers("/api/v1/eventos").permitAll()
                        .pathMatchers("/api/v1/eventos/listarEventos").permitAll()
                        .pathMatchers("/api/v1/eventos/buscarEvento/**").permitAll()
                        .pathMatchers("/api/v1/Eventos/**").permitAll()
                        // ═ Carrito — solo creación guest ═
                        .pathMatchers("/api/v1/Carrito/crear").permitAll()
                        .pathMatchers("/api/v1/carrito/crear").permitAll()
                        // ═ Donaciones / Causas — solo lectura pública ═
                        .pathMatchers("/api/v1/causas/activas").permitAll()
                        .pathMatchers("/api/v1/organizaciones").permitAll()
                        .pathMatchers("/api/v1/organizaciones/todas").permitAll()
                        // ═ Todo lo demás requiere autenticación ═
                        .anyExchange().authenticated()
                )
                .build();
    }
}
