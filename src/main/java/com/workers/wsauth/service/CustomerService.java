package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    public Boolean registerNewCustomer(AuthRequest request) {
        try {
            Customer newCustomer = new Customer();
            newCustomer.setUserName(request.username());
            newCustomer.setPassword(passwordEncoder.encode(request.password()));
            newCustomer.setEnabled(false);
            customerRepository.save(newCustomer);
            return true;
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(BAD_REQUEST, "Пользователь " + request.username() + " уже существует.");
        }
    }
}
