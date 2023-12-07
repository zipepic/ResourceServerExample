package com.example.oauthresourceserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.project.core.queries.user.FetchJwkSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.axonframework.messaging.responsetypes.ResponseTypes;
import org.axonframework.queryhandling.QueryGateway;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import tokenlib.util.jwk.RSAParser;
import tokenlib.util.jwk.SimpleJWK;

import java.text.ParseException;
import java.util.Objects;

public class AxonJwtDecoder implements JwtDecoder {
    private final QueryGateway queryGateway;

    public AxonJwtDecoder(QueryGateway queryGateway) {
        this.queryGateway = queryGateway;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Objects.requireNonNull(queryGateway, "queryGateway must not be null");
        Objects.requireNonNull(token, "token must not be null");

        var query = FetchJwkSet.builder().build();
        var jwks = queryGateway.query(query, ResponseTypes.multipleInstancesOf(SimpleJWK.class)).join();
        var kid = extractKid(token);
        var simleJwk = jwks.stream().filter(j -> j.getKid().equals(kid)).findFirst().orElseThrow();

        RSAKey rsaKey;
        try {
            rsaKey = RSAParser.parseRSAKeyFromSimpleJWK(simleJwk);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error parsing RSA key from SimpleJWK", e);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            if (!signedJWT.verify(verifier)) {
                throw new RuntimeException("Invalid signature");
            }
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Error verifying signature", e);
        }

        // Возвращаем Jwt после успешной проверки подписи
        return Jwt.withTokenValue(token).build();
    }
    private String extractKid(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder().build().parseClaimsJws(token);
        String kid = (String) claimsJws.getHeader().get("kid");
        return kid;
    }

}
