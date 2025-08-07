package com.example.auth_client_starter.components;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;

import com.example.auth_client_starter.utils.AuthUtils;

import reactor.core.publisher.Mono;

public class CustomReactiveAuthorizationServiceIntrospector implements ReactiveOpaqueTokenIntrospector{
    // private final Logger log = LoggerFactory.getLogger(CustomReactiveAuthorizationServiceIntrospector.class);

    @Autowired
    private AuthUtils authUtils;

    // public CustomReactiveAuthorizationServiceIntrospector(AuthUtils authUtils){
    //     this.authUtils = authUtils;
    // }

    @Override
    public Mono<OAuth2AuthenticatedPrincipal> introspect(String accessTokenValue) {
        return Mono.just(accessTokenValue)
                .map(token -> authUtils.checkAccessTokenToAuth(accessTokenValue))
                .map(this :: convertClaimsSet)
                .onErrorMap((e) -> !(e instanceof OAuth2IntrospectionException), this::onError);
    }

    private OAuth2AuthenticatedPrincipal convertClaimsSet(
        OAuth2Authorization authorization
    ){
        Map<String, Object> claims = new HashMap<>();

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        claims.putAll(authorization.getAttributes());

        Authentication authentication = (Authentication)authorization.getAttributes().get(Principal.class.getName());

        if (authentication != null) {
            authorities.addAll(authentication.getAuthorities());
        }

        return new OAuth2IntrospectionAuthenticatedPrincipal(authorization.getPrincipalName(), claims, authorities);
    }

    private OAuth2IntrospectionException onError(Throwable ex) {
        return new OAuth2IntrospectionException(ex.getMessage(), ex);
    }
}
