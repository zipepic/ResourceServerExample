package com.example.oauthresourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class OauthResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthResourceServerApplication.class, args);
    }

}
