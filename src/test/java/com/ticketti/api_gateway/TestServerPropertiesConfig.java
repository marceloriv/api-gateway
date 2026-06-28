package com.ticketti.api_gateway;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.boot.webflux.autoconfigure.WebFluxProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.codec.ServerCodecConfigurer;

@TestConfiguration
public class TestServerPropertiesConfig {

    @Bean
    @ConditionalOnMissingBean(ServerProperties.class)
    public ServerProperties serverProperties() {
        return new ServerProperties();
    }

    @Bean
    @ConditionalOnMissingBean(WebFluxProperties.class)
    public WebFluxProperties webFluxProperties() {
        return new WebFluxProperties();
    }

    @Bean("testServerCodecConfigurer")
    @ConditionalOnMissingBean
    @Primary
    public ServerCodecConfigurer testServerCodecConfigurer() {
        return ServerCodecConfigurer.create();
    }

}
