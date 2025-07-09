package com.devconnect.devconnect.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;


@Getter
@AllArgsConstructor
public class SignupResponse {
    private String message;
    private Long userId;
}