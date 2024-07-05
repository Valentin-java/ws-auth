package com.workers.wsauth.rest.handlers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

@ControllerAdvice
public class AuthErrorHandler {

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<String> handle(ResponseStatusException e) {
        return handleResponseStatusException(e);
    }

    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<String> handle(BadCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(LockedException.class)
    ResponseEntity<String> handle(LockedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    private ResponseEntity<String> handleResponseStatusException(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode().value()).body(e.getReason());
    }
}
