package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.entity.Role;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.persistence.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final CustomerRepository customerRepository;
    private final RoleRepository roleRepository;

    public void assignRoleToUser(String username, String roleName) {
        Customer customer = customerRepository.findCustomerByUserName(username)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Пользователь не найден"));

        Role role = roleRepository.findByRole(roleName);
        if (role == null) {
            throw new RuntimeException("Role not found");
        }

        customer.getRoles().add(role);
        customerRepository.save(customer);
    }
}
