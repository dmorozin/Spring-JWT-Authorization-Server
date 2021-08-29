package com.authserver.controller;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@RestController
public class TokenController {

    private final JWKSet jwkSet;
    private final KeyPair keyPair;

    @Autowired
    public TokenController(JWKSet jwkSet, KeyPair keyPair) {

        this.jwkSet = jwkSet;
        this.keyPair = keyPair;
    }

    @GetMapping("/token")
    public String getToken(@RequestParam(value = "scope", required = false) String scope) {

        Instant now = Instant.now();
        long expiry = 3600L;

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("Dominik")
                .issueTime(new Date(now.toEpochMilli()))
                .expirationTime(new Date(now.plusSeconds(expiry).toEpochMilli()))
                .subject("user")
                .claim("scope", scope)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT jwt = sign(new SignedJWT(header, claims));

        return jwt.serialize();
    }

    @GetMapping("/jwks.json")
    public Map<String, Object> keys() {

        return jwkSet.toJSONObject();
    }

    private SignedJWT sign(SignedJWT jwt) {

        try {
            jwt.sign(new RSASSASigner(keyPair.getPrivate()));
            return jwt;
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}