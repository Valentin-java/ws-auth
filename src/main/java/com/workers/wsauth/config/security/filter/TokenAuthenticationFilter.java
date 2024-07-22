package com.workers.wsauth.config.security.filter;

import com.workers.wsauth.config.security.context.TokenAuthenticationFilterContext;
import com.workers.wsauth.config.security.util.SecurityValidationUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static com.workers.wsauth.config.security.util.Constants.UNEXPECTED_TEXT_ERROR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final SecurityValidationUtil securityUtil;

    private static final List<String> WHITELIST = List.of(
            "/actuator/health",
            "/actuator/prometheus",
            "/advisor",
            "/swagger-ui",
            "/specs",
            "/v1/workers/auth/login");

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws IOException, ServletException {

        if (WHITELIST.contains(request.getRequestURI())) {
            filterChain.doFilter(request, response);
        } else {
            doFilterRequest(request, response, filterChain);
        }
    }

    private void doFilterRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        log.debug("[doFilterInternal] Start method");
        try {
            Optional.of(createContextFilter(request, response, filterChain))
                    .map(this::validateHeader)
                    .map(this::tokenContainUsername)
                    .map(this::validateTokenExpiration)
                    .map(this::setAuthenticationContext)
                    .ifPresent(this::continueFilterChain);
        } catch (ResponseStatusException e) {
            log.error("Authentication error: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(e.getMessage());
        }
    }


    private TokenAuthenticationFilterContext createContextFilter(HttpServletRequest request,
                                                                 HttpServletResponse response,
                                                                 FilterChain filterChain) {
        return new TokenAuthenticationFilterContext(request, response, filterChain);
    }

    private TokenAuthenticationFilterContext validateHeader(TokenAuthenticationFilterContext context) {
        if (securityUtil.whenHeaderMissing(context)) {
            throw new ResponseStatusException(UNAUTHORIZED, "Отсуствует, либо заголовок, либо токен");
        }
        return context;
    }

    private TokenAuthenticationFilterContext tokenContainUsername(TokenAuthenticationFilterContext context) {
        if (securityUtil.whenUsernameMissing(context)) {
            log.error("Token provided but not content data!");
            throw new ResponseStatusException(UNAUTHORIZED, "В токене отсуствует имя пользователя");
        }
        return context;
    }

    private TokenAuthenticationFilterContext validateTokenExpiration(TokenAuthenticationFilterContext context) {
        if (securityUtil.whenTokenExpired(context)) {
            log.error("[validateTokenExpiration] Время жизни токена истекло.");
            throw new ResponseStatusException(UNAUTHORIZED, "Время жизни токена истекло");
        }
        return context;
    }

    private TokenAuthenticationFilterContext setAuthenticationContext(TokenAuthenticationFilterContext context) {
        String username = securityUtil.getUsername(context);
        log.debug("[setAuthenticationContext] username: {}", username);

        var grantedAuthorities = securityUtil.getGrantedAuthority(context);

        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return context;
    }

    private void continueFilterChain(TokenAuthenticationFilterContext context) {
        try {
            context.getFilterChain().doFilter(context.getRequest(), context.getResponse());
        } catch (IOException | ServletException e) {
            throw new ResponseStatusException(UNAUTHORIZED, UNEXPECTED_TEXT_ERROR);
        }
    }
}
