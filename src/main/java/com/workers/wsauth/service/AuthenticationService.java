package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthRequest;
import com.workers.wsauth.rest.dto.AuthResponse;
import com.workers.wsauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse authenticate(AuthRequest request) {
        return Optional.of(request)
                .map(this::validateUserActivity)
                .map(this::validatePassword)
                .map(this::createAuthenticationResponse)
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "[AuthenticationService -> authenticate] Что-то пошло не так"));
    }

    private AuthRequest validateUserActivity(AuthRequest request) {
        if (customerRepository.existsCustomerByUserNameAndEnabled(request.username(), Boolean.TRUE)) return request;
        throw new ResponseStatusException(BAD_REQUEST, "Введен неверный пароль");
    }

    private Customer validatePassword(AuthRequest request) {
        var customer = customerRepository.findCustomerByUserNameAndEnabled(request.username(), Boolean.TRUE);
        if (request.otp() && customer != null) return customer;
        if (customer != null
                && passwordEncoder.matches(request.password(), customer.getPassword())) {
            return customer;
        }
        throw new ResponseStatusException(BAD_REQUEST, "Введен неверный пароль");
    }

    public AuthResponse createAuthenticationResponse(Customer customer) {
        final String accessToken = jwtUtil.generateToken(customer);
        final String refreshToken = jwtUtil.generateRefreshToken(customer);
        return new AuthResponse(accessToken, refreshToken);
    }

    public void activationCustomer(AuthRequest request) {
        Optional.of(request)
                .map(this::getCustomer)
                .map(this::validateUserActivity)
                .map(this::activateCustomer)
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "[AuthenticationService -> activationCustomer]  Что-то пошло не так"));
    }

    private Customer getCustomer(AuthRequest request) {
        return customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "Пользователь не найден"));
    }

    private Customer validateUserActivity(Customer request) {
        if (!request.isEnabled()) {
            return request;
        }
        throw new ResponseStatusException(BAD_REQUEST, "Пользователь уже активирован");
    }

    private boolean activateCustomer(Customer request) {
        request.setEnabled(true);
        customerRepository.save(request);
        return true;
    }

    public void validateToken(String token) {
        if (jwtUtil.validateToken(token) == null) {
            throw new ResponseStatusException(BAD_REQUEST, "Токен не валидный");
        }
    }

    public void logout(String token) {
        jwtUtil.invalidateToken(token);
    }
}
