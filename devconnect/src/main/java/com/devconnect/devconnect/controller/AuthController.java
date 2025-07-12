package com.devconnect.devconnect.controller;

import com.devconnect.devconnect.dto.*;
import com.devconnect.devconnect.security.JwtUtil;
import com.devconnect.devconnect.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest request) {
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.ok(Map.of("message", "로그아웃 성공"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(HttpServletRequest request) {
        String refreshToken = jwtUtil.extractToken(request);
        LoginResponse newTokens = authService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(newTokens);
    }

    @GetMapping("/me")
    public ResponseEntity<String> getUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body("인증되지 않았습니다.");
        }

        String userId = (String) authentication.getPrincipal();
        return ResponseEntity.ok("현재 로그인한 사용자 ID: " + userId);
    }
}