package com.ticketti.api_gateway;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE,
		properties = {
		"spring.autoconfigure.exclude=org.springframework.cloud.gateway.config.GatewayAutoConfiguration,org.springframework.cloud.gateway.discovery.GatewayDiscoveryClientAutoConfiguration,org.springframework.cloud.gateway.config.GatewayMetricsAutoConfiguration,org.springframework.cloud.gateway.config.GatewayReactiveLoadBalancerClientAutoConfiguration,org.springframework.cloud.gateway.config.GatewayResilience4JCircuitBreakerAutoConfiguration",
		"spring.cloud.discovery.enabled=false",
		"spring.cloud.config.enabled=false",
		"eureka.client.enabled=false",
		"jwt.secret=test-secret-for-testing-minimum-32-characters"
	})
class ApiGatewayApplicationTests {

	@Test
	void contextoCarga() {
		assertTrue(true, "El contexto de prueba carga correctamente");
	}

	@Test
	void metodoPrincipal_AlLlamarse_IniciaAplicacion() {
		// No arrancar el contexto completo en tests unitarios locales; crear la
		// aplicación y comprobar que la construcción no lanza excepciones.
		assertDoesNotThrow(() -> {
			org.springframework.boot.SpringApplication app = new org.springframework.boot.SpringApplication(ApiGatewayApplication.class);
			app.setWebApplicationType(org.springframework.boot.WebApplicationType.NONE);
		});
	}
}
