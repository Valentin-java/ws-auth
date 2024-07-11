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

    public Boolean requestToResetPassword(AuthRequest request) {
        Customer customer = customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "Не удалось найти пользователя: " + request.username()));
        customer.setPassword(null);
        customer.setEnabled(false);
        customerRepository.save(customer);
        return true;
    }

    public Boolean requestToChangePassword(AuthRequest request) {
        Customer customer = customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "Не удалось найти пользователя: " + request.username()));
        customer.setPassword(passwordEncoder.encode(request.password()));
        customer.setEnabled(true);
        customerRepository.save(customer);
        return true;
    }
}
