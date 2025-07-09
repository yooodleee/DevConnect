package com.devconnect.devconnect.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
public class SignupRequest {
    private String email;
    private String password;
    private String nickname;
}