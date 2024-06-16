package com.workers.wsauth.service;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return customerRepository.findCustomerByUserName(username)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Пользователь не найден с именем: " + username));
    }
}
