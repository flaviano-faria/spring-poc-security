package com.javabridge.springpocsecurity.security.filter;

import com.javabridge.springpocsecurity.configuration.SecurityConfiguration;
import com.javabridge.springpocsecurity.entities.User;
import com.javabridge.springpocsecurity.impl.UserDetailsImpl;
import com.javabridge.springpocsecurity.repository.UserRepository;
import com.javabridge.springpocsecurity.security.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Component
public class UserAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Skip authentication for public endpoints
        if (!checkIfEndpointIsNotPublic(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract and validate JWT token
        String token = recoveryToken(request);
        if (token != null) {
            try {
                // Validate token and extract username
                String subject = jwtTokenService.getUsernameFromToken(token);
                Optional<User> user = userRepository.findByEmail(subject);
                
                if (user.isPresent()) {
                    UserDetailsImpl userDetails = new UserDetailsImpl(user.get());
                    
                    // Create authentication object
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            userDetails.getUsername(),
                            null,
                            userDetails.getAuthorities()
                    );
                    
                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // Token validation failed - let Spring Security handle unauthorized access
                SecurityContextHolder.clearContext();
            }
        }
        
        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    private String recoveryToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }
        return null;
    }

    private boolean checkIfEndpointIsNotPublic(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return !Arrays.asList(SecurityConfiguration.NOT_REQUIRED_AUTH).contains(requestURI);
    }
}
