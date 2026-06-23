package com.ticketti.api_gateway.config;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.ticketti.api_gateway.filter.JwtAuthenticationWebFilter;

class SecurityConfigTest {

    private final JwtAuthenticationWebFilter jwtWebFilter = mock(JwtAuthenticationWebFilter.class);
    private final SecurityConfig securityConfig = new SecurityConfig(jwtWebFilter);

    @Test
    void configuracionSeguridad_NoEsNula() {
        assertNotNull(securityConfig);
    }

    @Test
    void cadenaFiltrosSeguridad_AlLlamarse_RetornaCadenaFiltrosSeguridad() {
        ServerHttpSecurity http = ServerHttpSecurity.http();
        SecurityWebFilterChain filterChain = securityConfig.springSecurityFilterChain(http);

        assertNotNull(filterChain);
        assertTrue(filterChain instanceof SecurityWebFilterChain);
    }
}
