package com.workers.wsauth.rest.controllers;

import com.workers.wsauth.rest.dto.AssignRoleRequest;
import com.workers.wsauth.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/workers/auth")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @PostMapping("/assign-role")
    public ResponseEntity<?> assignRole(@RequestBody AssignRoleRequest request) {
        roleService.assignRoleToUser(request.username(), request.role());
        return ResponseEntity.ok("Role assigned successfully");
    }
}
