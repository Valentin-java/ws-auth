package com.workers.wsauth.rest.dto;

public record AuthenticationResponse(
        String accessToken, String refreshToken
) {
}
