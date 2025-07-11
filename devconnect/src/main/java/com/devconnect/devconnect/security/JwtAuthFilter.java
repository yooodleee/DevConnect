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

import java.io.IOException;
import java.util.Collections;


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

            if (token.equals(redisToken)) {
                logger.info("[JwtAuthFilter] Token validated, setting SecurityContext");

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList()); // 권한 X
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
}