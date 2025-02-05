package org.tawhid.rentapp.auth.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private long jwtExpirationInMs;
    private SecretKey key;
    @PostConstruct
    public void init() {
        // Now jwtSecret has been injected, so you can safely use it
        key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
    /**
     * Generates a JWT token for the provided email.
     */


    public String generateToken(String email) {
        Date now = new Date();
        Date expiriDate = new Date(now.getTime() + jwtExpirationInMs);
        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiriDate)
                .signWith(key).compact();
    }

    /**
     * Extracts the email (subject) from the JWT token.
     */

    public String getEmailFromToken(String token) {// Convert secret to a proper key

        Claims claims = Jwts.parser()
                .verifyWith(key)  // New method in jjwt 0.12.6
                .build()
                .parseSignedClaims(token) // Use parseSignedClaims() instead of parseClaimsJws()
                .getPayload(); // Extract claims

        return claims.getSubject();
    }
    /**
     * Validates the JWT token.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (Exception ex) {
            // Log exception details in a real application
            return false;
        }
    }
}
