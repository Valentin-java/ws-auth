package com.workers.wsauth.rest.dto;

public record AuthRequest(
        String username,
        String password
) {
}
