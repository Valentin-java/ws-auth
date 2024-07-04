package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthRequest;
import com.workers.wsauth.rest.dto.AuthResponse;
import com.workers.wsauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthResponse authenticate(AuthRequest request) {
        return Optional.of(request)
                .map(this::validateUserActivity)
                .map(this::getAuthentication)
                .map(this::validateAuthentication)
                .map(this::setAuthenticationContext)
                .map(this::createAuthenticationResponse)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Что-то пошло не так"));
    }

    private AuthRequest validateUserActivity(AuthRequest request) {
        if (customerRepository.findCustomerByUserNameAndEnabled(request.username(), Boolean.TRUE) != null) {
            return request;
        }
        throw new ResponseStatusException(UNAUTHORIZED, "Пользователь не активирован");
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

    public AuthResponse createAuthenticationResponse(Customer customer) {
        final String accessToken = jwtUtil.generateToken(customer);
        final String refreshToken = jwtUtil.generateRefreshToken(customer);
        return new AuthResponse(accessToken, refreshToken);
    }

    public Boolean activationCustomer(AuthRequest request) {
        return Optional.of(request)
                .map(this::getCustomer)
                .map(this::validateUserActivity)
                .map(this::activateCustomer)
                .orElseThrow(() -> new ResponseStatusException(OK, "Что-то пошло не так"));
    }

    private Customer getCustomer(AuthRequest request) {
        return customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(OK, "Пользователь не найден"));
    }

    private Customer validateUserActivity(Customer request) {
        if (!request.isEnabled()) {
            return request;
        }
        throw new ResponseStatusException(OK, "Пользователь уже активирован");
    }

    private boolean activateCustomer(Customer request) {
        request.setEnabled(true);
        customerRepository.save(request);
        return true;
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateToken(token) != null;
    }

    public void logout(String token) {
        jwtUtil.invalidateToken(token);
    }
}
