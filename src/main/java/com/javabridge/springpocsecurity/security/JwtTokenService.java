package com.javabridge.springpocsecurity.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for JWT token generation, validation, and parsing.
 * Provides methods to create, verify, and extract information from JWT tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtTokenService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400000}")
    private Long jwtExpiration;

    @Value("${jwt.issuer:spring-poc-security}")
    private String jwtIssuer;

    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_EMAIL = "email";

    /**
     * Generates a JWT token for the authenticated user.
     *
     * @param userDetails the UserDetails object containing user information
     * @return the generated JWT token as a string
     * @throws JWTCreationException if token creation fails
     */
    public String generateToken(UserDetails userDetails) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);

            Instant now = Instant.now();
            Instant expiration = now.plus(jwtExpiration, ChronoUnit.MILLIS);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return JWT.create()
                    .withIssuer(jwtIssuer)
                    .withSubject(userDetails.getUsername())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(expiration))
                    .withClaim(CLAIM_EMAIL, userDetails.getUsername())
                    .withClaim(CLAIM_ROLES, roles)
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            log.error("Error creating JWT token", e);
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }

    /**
     * Generates a JWT token with additional user information.
     *
     * @param userDetails the UserDetails object containing user information
     * @param userId the user ID to include in the token
     * @return the generated JWT token as a string
     * @throws JWTCreationException if token creation fails
     */
    public String generateToken(UserDetails userDetails, Long userId) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);

            Instant now = Instant.now();
            Instant expiration = now.plus(jwtExpiration, ChronoUnit.MILLIS);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return JWT.create()
                    .withIssuer(jwtIssuer)
                    .withSubject(userDetails.getUsername())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(expiration))
                    .withClaim(CLAIM_USER_ID, userId)
                    .withClaim(CLAIM_EMAIL, userDetails.getUsername())
                    .withClaim(CLAIM_ROLES, roles)
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            log.error("Error creating JWT token with user ID", e);
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }

    /**
     * Validates a JWT token and returns the decoded token if valid.
     *
     * @param token the JWT token to validate
     * @return the decoded JWT token
     * @throws JWTVerificationException if token validation fails
     */
    public DecodedJWT validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwtIssuer)
                    .build();
            return verifier.verify(token);
        } catch (JWTVerificationException e) {
            log.warn("JWT token validation failed: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    /**
     * Extracts the username (subject) from a JWT token.
     *
     * @param token the JWT token
     * @return the username extracted from the token
     */
    public String getUsernameFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getSubject();
    }

    /**
     * Extracts the user ID from a JWT token.
     *
     * @param token the JWT token
     * @return the user ID, or null if not present
     */
    public Long getUserIdFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getClaim(CLAIM_USER_ID).asLong();
    }

    /**
     * Extracts the email from a JWT token.
     *
     * @param token the JWT token
     * @return the email extracted from the token
     */
    public String getEmailFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getClaim(CLAIM_EMAIL).asString();
    }

    /**
     * Extracts the roles from a JWT token.
     *
     * @param token the JWT token
     * @return list of role names
     */
    public List<String> getRolesFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getClaim(CLAIM_ROLES).asList(String.class);
    }

    /**
     * Checks if a JWT token is expired.
     *
     * @param token the JWT token to check
     * @return true if the token is expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            DecodedJWT decodedJWT = validateToken(token);
            Date expiration = decodedJWT.getExpiresAt();
            return expiration.before(new Date());
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Extracts the expiration date from a JWT token.
     *
     * @param token the JWT token
     * @return the expiration date, or null if not present
     */
    public Date getExpirationDateFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getExpiresAt();
    }

    /**
     * Extracts the issued date from a JWT token.
     *
     * @param token the JWT token
     * @return the issued date, or null if not present
     */
    public Date getIssuedDateFromToken(String token) {
        DecodedJWT decodedJWT = validateToken(token);
        return decodedJWT.getIssuedAt();
    }
}
