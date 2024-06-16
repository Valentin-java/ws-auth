package com.workers.wsauth.rest.controllers;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.rest.dto.AuthRequest;
import com.workers.wsauth.rest.dto.AuthenticationResponse;
import com.workers.wsauth.service.AuthenticationService;
import com.workers.wsauth.service.CustomerService;
import com.workers.wsauth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/workers/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final CustomerService customerService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<?> registerCustomer(@RequestBody AuthRequest request) {
        Customer customer = customerService.registerNewCustomer(request);
        return ResponseEntity.ok(customer);
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest request) {
        AuthenticationResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestParam String token) {
        AuthenticationResponse response = refreshTokenService.refreshToken(token);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestParam String token) {
        if (authenticationService.validateToken(token)) {
            return ResponseEntity.ok("Valid token");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String token) {
        authenticationService.logout(token);
        return ResponseEntity.ok("Successfully logged out");
    }
}
