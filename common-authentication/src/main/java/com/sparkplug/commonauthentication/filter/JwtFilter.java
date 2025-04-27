package com.sparkplug.commonauthentication.filter;

import com.sparkplug.commonauthentication.contract.PublicKeyProvider;
import com.sparkplug.commonauthentication.user.SparkplugUserDetails;
import com.sparkplug.commonauthentication.util.JwtValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final PublicKeyProvider publicKeyProvider;

    @Autowired
    public JwtFilter(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            int tokenStartIndex = 7; //token starts after "Bearer "
            token = authHeader.substring(tokenStartIndex);
        }

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            var jwtValidator = new JwtValidator(token, publicKeyProvider.getPublicKey());
            if (!jwtValidator.validateExpiration()) {
                throw new AuthorizationDeniedException("JWT is expired.");
            }

            var userDetails = new SparkplugUserDetails(
                    Long.valueOf(jwtValidator.extract("id", Integer.class)),
                    jwtValidator.extract("email", String.class),
                    jwtValidator.extract("phoneNumber", String.class),
                    jwtValidator.extractAsList("authorities", String.class),
                    null,
                    jwtValidator.extract("username", String.class)
            );

            var authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            authToken
                    .setDetails(new WebAuthenticationDetailsSource()
                    .buildDetails(request));

            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
        }

        filterChain.doFilter(request, response);
    }

}
