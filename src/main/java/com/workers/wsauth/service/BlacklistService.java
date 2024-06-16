package com.workers.wsauth.service;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Service
public class BlacklistService {

    private final Set<String> blacklistedTokens = Collections.synchronizedSet(new HashSet<>());

    public void addTokenToBlacklist(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
}
