package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    public Customer registerNewCustomer(AuthRequest request) {
        try {
            Customer newCustomer = new Customer();
            newCustomer.setUserName(request.username());
            newCustomer.setPassword(passwordEncoder.encode(request.password()));
            newCustomer.setEnabled(true);
            return customerRepository.save(newCustomer);
        } catch (DataIntegrityViolationException e) {
            throw new RuntimeException("Username " + request.username() + " is already taken.");
        }
    }
}
