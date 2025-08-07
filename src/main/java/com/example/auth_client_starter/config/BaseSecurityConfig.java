package com.example.auth_client_starter.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.UUID;

import org.redisson.api.RBucket;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;

// import com.example.auth_client_starter.common.utils.ResponseUtils;
import com.example.auth_client_starter.enums.TokenType;
import com.example.auth_client_starter.properties.SecurityProperties;
import com.example.auth_client_starter.service.impl.RedisOAuth2AuthorizationService;
import com.example.common.constants.SecurityConstants;
import com.example.common.utils.ResponseUtils;
import com.example.common.utils.WebfluxResponseUtills;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.redisson.api.RedissonClient;
// import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;

// import com.example.auth_client_starter.common.constants.SecurityConstants;
// import com.example.auth_client_starter.common.utils.WebfluxResponseUtills;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
// import com.nimbusds.oauth2.sdk.Request;

@Configuration
public class BaseSecurityConfig {

    //luu tru
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(
        SecurityProperties securityProperties,
        RedissonClient redisson
    ){
        String tokenType = securityProperties.getResourceServer().getTokenType();

        if(TokenType.MEMORY.getName().equals(tokenType)){
            return new InMemoryOAuth2AuthorizationService();
        }

        return new RedisOAuth2AuthorizationService(securityProperties, redisson);
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(ObjectMapper objectMapper){
        return (request, response,authException) -> ResponseUtils.responseFailed(objectMapper, response, authException.getMessage());
    }

    @Bean
    public ServerAuthenticationEntryPoint serverAuthenticationEntryPoint(ObjectMapper objectMapper){
        return (exchange, e) -> WebfluxResponseUtills.responseFailed(exchange, HttpStatus.FORBIDDEN.value(), e.getMessage());
    }

    @Bean
    public AccessDeniedHandler oAuth2AccessDeniedHandler(ObjectMapper objectMapper){
        return (request, response, authException) -> ResponseUtils.responseFailed(objectMapper, response, authException.getMessage());
    }

    @Bean
    public ServerAccessDeniedHandler serverAccessDeniedHandler(){
        return (exchange, e) -> WebfluxResponseUtills.responseFailed(exchange, HttpStatus.FORBIDDEN.value(), e.getMessage());
    }

    private static KeyPair generateRsaKey(){
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e); 
        }

        return keyPair;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RedissonClient redisson) throws ParseException {
        RBucket<String> rBucket = redisson.getBucket(SecurityConstants.AUTHORIZATION_JWS_PREFIX_KEY);

        String jwkSetCache = rBucket.get();

        JWKSet jwkSet;

        if(jwkSetCache == null){
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();

            jwkSet = new JWKSet(rsaKey);
            String jwkSeString = jwkSet.toString(Boolean.FALSE);

            boolean success = rBucket.setIfAbsent(jwkSeString);
            if(!success){
                jwkSetCache = rBucket.get();
                jwkSet = JWKSet.parse(jwkSetCache);
            }
        } else{
            jwkSet = JWKSet.parse(jwkSetCache);
        }

        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }
}
