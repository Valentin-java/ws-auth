package com.workers.wsauth.util;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.entity.Role;
import com.workers.wsauth.persistence.repository.CustomerRepository;
import com.workers.wsauth.service.BlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {

    @Value("${jwt.private.key}")
    private String privateKeyString;

    @Value("${jwt.public.key}")
    private String publicKeyString;

    @Value("${jwt.access-token.expiration}")
    private long accessTokenExp;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExp;

    private final BlacklistService blacklistService;
    private final CustomerRepository customerRepository;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        privateKey = getPrivateKeyFromPem(privateKeyString);
        publicKey = getPublicKeyFromPem(publicKeyString);
    }

    public String generateToken(Customer customer) {
        return Jwts.builder()
                .subject(customer.getUsername())
                .claim("userId", customer.getId())
                .claim("roles", getRolesByCustomer(customer))
                .issuedAt(new Date())
                .expiration(calculateExpirationDate(accessTokenExp))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken(Customer customer) {
        return Jwts.builder()
                .subject(customer.getUsername())
                .claim("userId", customer.getId())
                .claim("roles", getRolesByCustomer(customer))
                .issuedAt(new Date())
                .expiration(calculateExpirationDate(refreshTokenExp))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    // Валидация токена для пользователя
    public Customer validateToken(String token) {
        return Optional.of(token)
                .map(this::checkBlackList)
                .map(this::extractAllClaims)
                .map(this::ensureTokenNotExpired)
                .map(this::validateUser)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Токен не валидный"));
    }

    private String checkBlackList(String token) {
        if (blacklistService.isTokenBlacklisted(token)) {
            return null;
        }
        return token;
    }

    // Извлечение всех параметров из токена
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Проверка истечения срока действия токена
    private Claims ensureTokenNotExpired(Claims claims) {
        return Optional.of(claims)
                .filter(claim -> !claim.getExpiration().before(new Date()))
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло"));
    }

    private Customer validateUser(Claims claims) {
        return customerRepository.findCustomerByUserName(claims.getSubject())
                .filter(Customer::getEnabled)
                .filter(cli -> claims.get("roles").equals(getRolesByCustomer(cli)))
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Пользователь не прошел валидацию соотвествия"));
    }

    private String getRolesByCustomer(Customer customer) {
        return new ArrayList<>(customer.getRoles()).stream().map(Role::getRole).collect(Collectors.joining(System.lineSeparator()));
    }

    public void invalidateToken(String token) {
        blacklistService.addTokenToBlacklist(token);
    }

    private PrivateKey getPrivateKeyFromPem(String privateKeyPEM) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(privateKeyPEM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            log.error("[getPublicKeyFromPem] Invalid private key");
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid private key");
        }
    }

    private PublicKey getPublicKeyFromPem(String publicKeyPEM) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(publicKeyPEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            log.error("[getPublicKeyFromPem] Invalid public key");
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid public key");
        }
    }

    private Date calculateExpirationDate(long expiration) {
        return new Date(System.currentTimeMillis() + expiration);
    }
}
