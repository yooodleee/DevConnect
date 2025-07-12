package com.devconnect.devconnect.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private String message;
    private String accessToken;
    private String refreshToken;
}