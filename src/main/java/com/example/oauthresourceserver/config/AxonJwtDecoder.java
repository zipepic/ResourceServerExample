package com.example.oauthresourceserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.project.core.queries.FetchJwksQuery;
import com.project.core.queries.user.FetchJwkSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.messaging.responsetypes.ResponseTypes;
import org.axonframework.queryhandling.QueryGateway;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import tokenlib.util.jwk.RSAParser;
import tokenlib.util.jwk.SimpleJWK;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Objects;
@Slf4j
public class AxonJwtDecoder implements JwtDecoder {
    private final QueryGateway queryGateway;

    public AxonJwtDecoder(QueryGateway queryGateway) {
        this.queryGateway = queryGateway;
    }
    //TODO optimize this method
    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            Objects.requireNonNull(queryGateway, "queryGateway must not be null");
            Objects.requireNonNull(token, "token must not be null");

            var query = FetchJwksQuery.builder().build();
            List<String> jwks = queryGateway.query(query, ResponseTypes.multipleInstancesOf(String.class)).join();
            var kid = extractKid(token);

            SimpleJWK simleJwk = SimpleJWK.parse(jwks.stream().filter(j -> j.contains(kid)).findFirst().orElseThrow());
            RSAKey rsaKey = RSAParser.parseRSAKeyFromSimpleJWK(simleJwk);

            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            if (!signedJWT.verify(verifier)) {
                throw new AccessDeniedException("Invalid signature");
            }

            if (signedJWT.getJWTClaimsSet().getExpirationTime() != null
                    && signedJWT.getJWTClaimsSet().getExpirationTime().before(new Date())) {
                throw new AccessDeniedException("Token has expired");
            }

            return Jwt.withTokenValue(token)
                    .header("kid", signedJWT.getHeader().getKeyID())
                    .header("alg", signedJWT.getHeader().getAlgorithm().getName())
                    .subject(signedJWT.getJWTClaimsSet().getSubject())
                    .issuer(signedJWT.getJWTClaimsSet().getIssuer())
                    .expiresAt(signedJWT.getJWTClaimsSet().getExpirationTime().toInstant())
                    .claim("token_type", signedJWT.getJWTClaimsSet().getClaim("token_type"))
                    .issuedAt(signedJWT.getJWTClaimsSet().getIssueTime().toInstant())
                    .build();

        } catch (Exception e) {
            log.error("Error decoding JWT: " + e.getMessage());
            throw new AccessDeniedException("Error decoding JWT: " + e.getMessage(), e);
        }
    }

    private String extractKid(String token) throws ParseException {
        return JWSObject.parse(token).getHeader().getKeyID();
    }



}
