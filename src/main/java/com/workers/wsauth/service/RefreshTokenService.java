package com.workers.wsauth.service;

import com.workers.wsauth.rest.dto.AuthResponse;
import com.workers.wsauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtUtil jwtUtil;
    private final AuthenticationService authenticationService;

    public AuthResponse refreshToken(String refreshToken) {
        return Optional.of(refreshToken)
                .map(jwtUtil::validateToken)
                .map(authenticationService::createAuthenticationResponse)
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "[RefreshTokenService -> refreshToken] Что-то пошло не так"));
    }
}
