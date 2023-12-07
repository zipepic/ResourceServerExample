package com.example.oauthresourceserver.config;

import org.axonframework.queryhandling.QueryGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
public class SecurityConfig {
    private final QueryGateway queryGateway;
    @Autowired
    public SecurityConfig(QueryGateway queryGateway) {
        this.queryGateway = queryGateway;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return new AxonJwtDecoder(queryGateway);
    }
}
