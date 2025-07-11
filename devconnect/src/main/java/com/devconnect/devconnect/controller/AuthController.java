package com.devconnect.devconnect.controller;

import com.devconnect.devconnect.dto.LoginRequest;
import com.devconnect.devconnect.dto.LoginResponse;
import com.devconnect.devconnect.dto.SignupRequest;
import com.devconnect.devconnect.dto.SignupResponse;
import com.devconnect.devconnect.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest request) {
        SignupResponse response = authService.signup(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/user/me")
    public ResponseEntity<String> getUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body("인증되지 않았습니다.");
        }

        String userId = (String) authentication.getPrincipal();
        return ResponseEntity.ok("현재 로그인한 사용자 ID: " + userId);
    }
}