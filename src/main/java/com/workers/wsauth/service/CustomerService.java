package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.rest.dto.AuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final static String BY_OTP_PASS = "BY_OTP";
    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    public void registerNewCustomer(AuthRequest request) {
        try {
            Customer newCustomer = new Customer();
            newCustomer.setUserName(request.username());
            Optional.ofNullable(request.otp())
                    .filter(Boolean.TRUE::equals)
                    .ifPresentOrElse(
                            byOtp -> newCustomer.setPassword(passwordEncoder.encode(BY_OTP_PASS)),
                            () -> newCustomer.setPassword(passwordEncoder.encode(request.password())));
            newCustomer.setEnabled(false);
            customerRepository.save(newCustomer);
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(BAD_REQUEST, "Пользователь " + request.username() + " уже существует.");
        }
    }

    public void requestToResetPassword(AuthRequest request) {
        Customer customer = customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "Не удалось найти пользователя: " + request.username()));
        customer.setPassword(null);
        customer.setEnabled(false);
        customerRepository.save(customer);
    }

    public void requestToChangePassword(AuthRequest request) {
        Customer customer = customerRepository.findCustomerByUserName(request.username())
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "Не удалось найти пользователя: " + request.username()));
        customer.setPassword(passwordEncoder.encode(request.password()));
        customer.setEnabled(true);
        customerRepository.save(customer);
    }
}
