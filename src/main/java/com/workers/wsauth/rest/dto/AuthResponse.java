package com.workers.wsauth.rest.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {
}
