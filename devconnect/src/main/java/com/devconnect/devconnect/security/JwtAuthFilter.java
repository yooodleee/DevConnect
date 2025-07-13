package com.devconnect.devconnect.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Collections;
import java.util.List;


@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    // Redis key prefix는 상수화 -> 버그 방지 & 유지 보수
    private static final String TOKEN_PREFIX = "TOKEN:";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);
        logger.info("[JwtAuthFIlter] Extracted Token: {}" + token);

        if (StringUtils.hasText(token) && jwtUtil.validateToken(token)) {
            String userId = jwtUtil.getUserIdFromToken(token);
            logger.info("[JwtAuthFilter] UserId from Token: {}" + userId);

            String redisToken = redisTemplate.opsForValue().get(TOKEN_PREFIX + userId);
            logger.info("[JwtAuthFilter] Redis Token: {}" + redisToken);

            String roleName = jwtUtil.getRoleFromToken(token); // 역할 추출
            logger.info("[JwtAuthFilter] Role Name from Token: {}" + roleName);

            if (token.equals(redisToken)) {
                logger.info("[JwtAuthFilter] Token validated, setting SecurityContext");

                // 권한 부여
                List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + roleName));

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities); // 권한 포함 
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                logger.warn("[JwtAuthFilter] Token mismatch with Redis");
            }
        } else {
            logger.warn("[JwtAuthFilter] Token is invalid or missing");
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (!StringUtils.hasText(bearerToken)) return null;
        if (!bearerToken.startsWith("Bearer ")) return null;
        return bearerToken.substring(7);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        boolean skip = path.startsWith("/api/auth/login") ||
                        path.startsWith("/api/auth/signup") ||
                        path.startsWith("/api/auth/refresh");
        logger.info("[JwtAuthFilter] shouldNotFilter for path: {}" + path);
        return skip;
    }
}