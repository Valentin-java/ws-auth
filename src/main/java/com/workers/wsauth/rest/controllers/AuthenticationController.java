package com.workers.wsauth.rest.controllers;

import com.workers.wsauth.rest.dto.AuthRequest;
import com.workers.wsauth.service.AuthenticationService;
import com.workers.wsauth.service.CustomerService;
import com.workers.wsauth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
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
    public ResponseEntity<Void> registerCustomer(@RequestBody AuthRequest request) {
        customerService.registerNewCustomer(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/activation")
    public ResponseEntity<Void> activationCustomer(@RequestBody AuthRequest request) {
        authenticationService.activationCustomer(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestParam String token) {
        return ResponseEntity.ok(refreshTokenService.refreshToken(token));
    }

    @GetMapping("/validate-token")
    public ResponseEntity<Void> validateToken(@RequestParam String token) {
        authenticationService.validateToken(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String token) {
        authenticationService.logout(token);
        return ResponseEntity.ok("Successfully logged out");
    }

    @PostMapping("/reset")
    public ResponseEntity<Void> requestToResetPassword(@RequestBody AuthRequest request) {
        customerService.requestToResetPassword(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/changepass")
    public ResponseEntity<Void> requestToChangePassword(@RequestBody AuthRequest request) {
        customerService.requestToChangePassword(request);
        return ResponseEntity.ok().build();
    }
}
