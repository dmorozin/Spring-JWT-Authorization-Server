package com.authserver.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwkAuthorizationServerConfiguration {

    private static final String KEY_STORE_FILE = "auth-jwt.jks";
    private static final String KEY_STORE_PASSWORD = "auth-pass";
    private static final String KEY_ALIAS = "oauth-jwt";
    private static final String JWK_KID = "auth-key-id";

    @Bean
    public KeyPair keyPair() {

        ClassPathResource ksFile = new ClassPathResource(KEY_STORE_FILE);
        KeyStoreKeyFactory ksFactory = new KeyStoreKeyFactory(ksFile, KEY_STORE_PASSWORD.toCharArray());
        return ksFactory.getKeyPair(KEY_ALIAS);
    }

    @Bean
    public JWKSet jwkSet() {

        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic()).keyUse(KeyUse.SIGNATURE)
                                                                                         .algorithm(JWSAlgorithm.RS256)
                                                                                         .keyID(JWK_KID);
        return new JWKSet(builder.build());
    }

}
