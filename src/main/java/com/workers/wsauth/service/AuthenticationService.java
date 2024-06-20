package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.rest.dto.AuthRequest;
import com.workers.wsauth.rest.dto.AuthenticationResponse;
import com.workers.wsauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthenticationResponse authenticate(AuthRequest request) {
        return Optional.of(request)
                .map(this::getAuthentication)
                .map(this::validateAuthentication)
                .map(this::setAuthenticationContext)
                .map(this::createAuthenticationResponse)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Что-то пошло не так"));
    }

    private Authentication getAuthentication(AuthRequest request) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));
    }

    private Authentication validateAuthentication(Authentication authentication) {
        if (!authentication.isAuthenticated()) {
            throw new ResponseStatusException(UNAUTHORIZED, "Пользователь не аутентифицирован");
        }
        return authentication;
    }

    private Customer setAuthenticationContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return (Customer) authentication.getPrincipal();
    }

    public AuthenticationResponse createAuthenticationResponse(Customer customer) {
        final String accessToken = jwtUtil.generateToken(customer);
        final String refreshToken = jwtUtil.generateRefreshToken(customer);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateToken(token) != null;
    }

    public void logout(String token) {
        jwtUtil.invalidateToken(token);
    }
}
