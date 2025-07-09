package com.devconnect.devconnect.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // auth 관련 모두 허용
                        .requestMatchers("/api/redis/**").permitAll()  // Redis 테스트 API 허용
                        .anyRequest().authenticated()
                )
                .httpBasic();  // 테스트용 기본 인증

        return http.build();
    }
}
