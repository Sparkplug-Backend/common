package com.sparkplug.commonauthentication.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtValidator {

    private final Claims claims;

    public JwtValidator(String token, PublicKey publicKey) {
        this.claims = Jwts.parser().verifyWith(publicKey).build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateExpiration() {
        var isExpired = claims.getExpiration().before(new Date());

        return !isExpired;
    }

    public <T> T extract(String claimName, Class<T> clazz) {
        Object claimValue = claims.get(claimName);
        if (claimValue == null)
            return null;

        if (!clazz.isInstance(claimValue)) {
            throw new IllegalArgumentException(
                    "Claim '" + claimName + "' is not of type " + clazz.getName() +
                            ". Actual type: " + claimValue.getClass().getName()
            );
        }

        return clazz.cast(claimValue);
    }

    public <T> List<T> extractAsList(String claimName, Class<T> elementType) {
        Object claimValue = claims.get(claimName);
        if (claimValue == null)
            return null;

        if (!(claimValue instanceof List<?> rawList))
            throw new IllegalArgumentException(
                    "Claim '" + claimName + "' is not a List. Actual type: " + claimValue.getClass().getName());

        try {
            return rawList.stream()
                    .map(element -> {
                        if (!elementType.isInstance(element)) {
                            throw new IllegalArgumentException(
                                    "Element in claim '" + claimName + "' is not of type " + elementType.getName() +
                                            ". Actual type: " + element.getClass().getName()
                            );
                        }
                        return elementType.cast(element);
                    })
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to extract claim '" + claimName + "' as List<" + elementType.getName() + ">", e);
        }
    }


}
