package com.javabridge.springpocsecurity.configuration;

import com.javabridge.springpocsecurity.security.filter.UserAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private UserAuthenticationFilter userAuthenticationFilter;

    public static final String [] NOT_REQUIRED_AUTH = {
            "/users/login",
            "/users"
    };

    public static final String [] REQUIRED_AUTH = {
            "/users/test"
    };

    public static final String [] ENDPOINTS_ADMIN = {
            "/users/test/administrator"
    };

    public static final String [] ENDPOINTS_CUSTOMER = {
            "/users/test/customer"
    };


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // Disable CSRF for stateless JWT-based API
                .csrf(csrf -> csrf.disable())
                // Configure session management as stateless (no session storage)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints that don't require authentication
                        .requestMatchers(NOT_REQUIRED_AUTH).permitAll()
                        // Endpoints that require authentication
                        .requestMatchers(REQUIRED_AUTH).authenticated()
                        // Admin-only endpoints (note: Spring Security automatically adds "ROLE_" prefix)
                        .requestMatchers(ENDPOINTS_ADMIN).hasRole("ADMINISTRATOR")
                        // Customer-only endpoints
                        .requestMatchers(ENDPOINTS_CUSTOMER).hasRole("CUSTOMER")
                        // Deny all other requests
                        .anyRequest().denyAll()
                )
                // Add custom JWT authentication filter before the default authentication filter
                .addFilterBefore(userAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
