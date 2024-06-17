package com.workers.wsauth.util;

import com.workers.wsauth.persistence.entity.Customer;
import com.workers.wsauth.persistence.entity.Role;
import com.workers.wsauth.service.BlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
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
                .expiration(new Date(System.currentTimeMillis() + accessTokenExp))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken(Customer customer) {
        return Jwts.builder()
                .subject(customer.getUsername())
                .claim("userId", customer.getId())
                .claim("roles", getRolesByCustomer(customer))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExp))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private String getRolesByCustomer(Customer customer) {
        return new ArrayList<>(customer.getRoles()).stream().map(Role::getRole).collect(Collectors.joining(System.lineSeparator()));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Извлечение определенного параметра из токена
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
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
    public Boolean isTokenExpired(Claims claims) {
        return !claims.getExpiration().before(new Date());
    }

    // Валидация токена для пользователя
    public Boolean validateToken(String token) {
        return Optional.of(token)
                .map(this::checkBlackList)
                .map(this::extractAllClaims)
                .map(this::isTokenExpired)
                .orElse(false);
    }

    private String checkBlackList(String token) {
        if (blacklistService.isTokenBlacklisted(token)) {
            return null;
        }
        return token;
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
            throw new IllegalArgumentException("Invalid private key", e);
        }
    }

    private PublicKey getPublicKeyFromPem(String publicKeyPEM) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(publicKeyPEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid public key", e);
        }
    }
}
