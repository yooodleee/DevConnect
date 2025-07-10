package com.devconnect.devconnect.service;

import com.devconnect.devconnect.entity.User;
import com.devconnect.devconnect.dto.SignupRequest;
import com.devconnect.devconnect.dto.SignupResponse;
import com.devconnect.devconnect.dto.LoginRequest;
import com.devconnect.devconnect.dto.LoginResponse;
import com.devconnect.devconnect.security.JwtUtil;
import com.devconnect.devconnect.repository.UserRepository;

import lombok.RequiredArgsConstructor;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.concurrent.TimeUnit;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public LoginResponse login(LoginRequest request) {
        // 1. 사용자 존재 여부 확인
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isEmpty()) {
            throw new RuntimeException("해당 이메일의 사용자가 존재하지 않습니다.");
        }

        User user = userOptional.get();

        // 2. 비밀번호 검증
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        // 3. JWT 생성
        String token = jwtUtil.generateToken(String.valueOf(user.getId()));

        // 4. Redis 저장 (토큰 만료 시간과 동일하게 설정)
        redisTemplate.opsForValue().set(
                "TOKEN:" + user.getId(), token, 24, TimeUnit.HOURS
        );

        // 5. 응답 반환
        return new LoginResponse("로그인 성공", token);
    }

    public SignupResponse signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 존재하는 이메일입니다.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .nickname(request.getNickname())
                .build();

        User savedUser = userRepository.save(user);

        return new SignupResponse("회원가입 성공", savedUser.getId());
    }
}
