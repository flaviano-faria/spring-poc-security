package com.javabridge.springpocsecurity.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    public static final String [] NOT_REQUIRED_AUTH = {
            "/users/login",
            "/users"
    };

}
