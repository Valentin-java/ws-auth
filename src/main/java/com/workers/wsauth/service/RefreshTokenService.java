package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthenticationResponse;
import com.workers.wsauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtUtil jwtUtil;
    private final CustomerRepository customerRepository;
    private final AuthenticationService authenticationService;

    public AuthenticationResponse refreshToken(String refreshToken) {
        return Optional.of(refreshToken)
                .map(jwtUtil::extractUsername)
                .map(this::validateEnabledUser)
                .map(authenticationService::createAuthenticationResponse)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Что-то пошло не так"));
    }

    private String validateEnabledUser(String username) {
        customerRepository.findCustomerByUserName(username)
                .filter(Customer::getEnabled)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Пользователь не активен"));
        return username;
    }
}
