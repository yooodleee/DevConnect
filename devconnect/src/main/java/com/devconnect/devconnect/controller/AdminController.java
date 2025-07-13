package com.devconnect.devconnect.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("관리자만 접근 가능한 API입니다.");
    }
}