package com.workers.wsauth.rest.dto;

public record AssignRoleRequest(
        String username, String role
) {
}
