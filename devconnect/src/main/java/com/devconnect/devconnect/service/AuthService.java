package com.devconnect.devconnect.service;

import com.devconnect.devconnect.entity.*;
import com.devconnect.devconnect.dto.*;
import com.devconnect.devconnect.security.JwtUtil;
import com.devconnect.devconnect.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.concurrent.TimeUnit;


@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String ACCESS_PREFIX = "ACCESS:";
    private static final String REFRESH_PREFIX = "REFRESH:";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public SignupResponse signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 존재하는 이메일입니다.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .nickname(request.getNickname())
                .role(Role.USER) // 기본 권한 설정
                .build();

        User savedUser = userRepository.save(user);

        return new SignupResponse("회원가입 성공", savedUser.getId());
    }

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
        String userId = String.valueOf(user.getId());
        String accessToken = jwtUtil.generateAccessToken(user.getId().toString(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId().toString(), user.getRole());

        // 4. Redis에 Access Token과 Refresh Token 저장 (토큰 만료 시간과 동일하게 설정)
        redisTemplate.opsForValue().set(
                ACCESS_PREFIX + userId, accessToken, 15, TimeUnit.MINUTES
        );
        redisTemplate.opsForValue().set(
                REFRESH_PREFIX + userId, refreshToken, 7, TimeUnit.DAYS
        );

        // 5. 응답 반환
        return new LoginResponse("로그인 성공", accessToken, refreshToken);
    }

    public void logout(HttpServletRequest request) {
        String token = jwtUtil.extractToken(request); // Authorization 헤더에서 추출
        if (token != null && jwtUtil.validateToken(token)) {
            String userId = jwtUtil.getUserIdFromToken(token);
            redisTemplate.delete(ACCESS_PREFIX + userId); // Redis 에서 Access Token 삭제
            redisTemplate.delete(REFRESH_PREFIX + userId); // Redis에서 Refresh Token 삭제
            SecurityContextHolder.clearContext(); // 선택 가능
        }
    }

    public LoginResponse refreshAccessToken(String oldRefreshToken) {
        // 1. Refresh Token 검증
        if (!jwtUtil.validateToken(oldRefreshToken)) {
            throw new RuntimeException("Refresh Token이 유효하지 않습니다.");
        }

        String userId = jwtUtil.getUserIdFromToken(oldRefreshToken);
        String redisToken = redisTemplate.opsForValue().get(REFRESH_PREFIX + userId);

        // 2. Redis 토큰 비교
        if (!oldRefreshToken.equals(redisToken)) {
            throw new RuntimeException("사용되었거나 위조된 Refresh Token입니다.");
        }

        // 3. 새 토큰 생성
        String newAccessToken = jwtUtil.generateAccessToken(userId, Role.USER);
        String newRefreshToken = jwtUtil.generateRefreshToken(userId, Role.USER);

        // 4. 기존 토큰 삭제
        redisTemplate.delete(ACCESS_PREFIX + userId);
        redisTemplate.delete(REFRESH_PREFIX + userId);

        // 5. 새 토큰 Redis에 저장
        redisTemplate.opsForValue().set(ACCESS_PREFIX + userId, newAccessToken, 15, TimeUnit.MINUTES);
        redisTemplate.opsForValue().set(REFRESH_PREFIX + userId, newRefreshToken, 7, TimeUnit.DAYS);

        return new LoginResponse("토큰 재발급 성공", newAccessToken, newRefreshToken);
    }
}
