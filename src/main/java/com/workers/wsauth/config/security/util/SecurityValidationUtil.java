package com.workers.wsauth.config.security.util;

import com.workers.wsauth.config.security.context.TokenAuthenticationFilterContext;
import com.workers.wsauth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

import static com.workers.wsauth.config.security.util.Constants.AUTH_HEADER_NAME;
import static com.workers.wsauth.config.security.util.Constants.AUTH_TOKEN_PREFIX;
import static java.util.stream.Collectors.toList;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityValidationUtil {

    private final JwtUtil jwtUtil;

    public Boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = jwtUtil.extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String getUsername(TokenAuthenticationFilterContext context) {
        return extractClaim(getToken(context), Claims::getSubject);
    }

    public String getToken(TokenAuthenticationFilterContext context) {
        String header = context.getRequest().getHeader(AUTH_HEADER_NAME);
        return header.replaceAll(AUTH_TOKEN_PREFIX, "");
    }

    public String getHeaderRequest(TokenAuthenticationFilterContext context) {
        return context.getRequest().getHeader(AUTH_HEADER_NAME);
    }

    public boolean whenHeaderMissing(TokenAuthenticationFilterContext context) {
        String header = getHeaderRequest(context);
        return Strings.isEmpty(header)
                || !header.startsWith(AUTH_TOKEN_PREFIX);
    }
    public boolean whenUsernameMissing(TokenAuthenticationFilterContext context) {
        return getUsername(context) == null;
    }

    public boolean whenTokenExpired(TokenAuthenticationFilterContext context) {
        var claims = jwtUtil.extractAllClaims(getToken(context));
        return isTokenExpired(claims);
    }

    public List<GrantedAuthority> getGrantedAuthority(TokenAuthenticationFilterContext context) {
        Claims claims = jwtUtil.extractAllClaims(getToken(context));
        String roles = (String) claims.get("roles");

        return Arrays.stream(roles.split(","))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(toList());
    }
}
