package com.workers.wsauth.persistence.repository;

import com.workers.wsauth.persistence.entity.Customer;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Long> {

    @EntityGraph("customer_roles")
    Optional<Customer> findCustomerByUserName(String userName);

    @EntityGraph("customer_roles")
    Customer findCustomerByUserNameAndEnabled(String userName, Boolean enabled);

    Boolean existsCustomerByUserNameAndEnabled(String userName, Boolean enabled);
}
