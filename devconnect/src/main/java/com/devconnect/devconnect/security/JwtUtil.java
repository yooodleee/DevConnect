package com.devconnect.devconnect.security;

import com.devconnect.devconnect.entity.Role; // Role enum import
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;


@Component
public class JwtUtil {

    private final Key key;

    private static final long ACCESS_TOKEN_TTL = 1000L * 60 * 15; // 15분
    private static final long REFRESH_TOKEN_TTL = 1000L * 60 * 60 * 24 * 7; // 7일

    public JwtUtil(@Value("${JWT_SECRET_KEY}") String secretKey) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    // Access Token 생성
    public String generateAccessToken(String userId, Role role) {
        return generateToken(userId, role, ACCESS_TOKEN_TTL);
    }

    // Refresh Token 생성
    public String generateRefreshToken(String userId, Role role) {
        return generateToken(userId, role, REFRESH_TOKEN_TTL);
    }

    // JWT 생성
    public String generateToken(String userId, Role role, long expiration) {
        return Jwts.builder()
                .setSubject(userId)
                .claim("role", role.name()) // 역할 포함
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT에서 userId 추출
    public String getUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // JWT에서 Role 추출
    public String getRoleFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("role", String.class); // "USER", "ADMIN" 등의 문자열 반환
    }

    // JWT 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String extractToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
