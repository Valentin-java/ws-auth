package com.workers.wsauth.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Data;
import org.hibernate.annotations.Immutable;

@Data
@Entity
@Table(name = "ws01_role", schema = "\"ws-auth\"")
@Immutable
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ws01_role_seq")
    @SequenceGenerator(name = "ws01_role_seq", sequenceName = "ws01_role_seq", allocationSize = 1)
    private Long id;

    @Column(name = "role")
    private String role;
}
