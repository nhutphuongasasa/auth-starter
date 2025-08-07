package com.example.auth_client_starter.components;

import java.security.Principal;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import com.example.auth_client_starter.constants.SecurityConstants;


public class CustomAuthorizationServiceIntrospector implements OpaqueTokenIntrospector {
    private final OAuth2AuthorizationService authorizationService;

    private static final Logger log = LoggerFactory.getLogger(CustomAuthorizationServiceIntrospector.class);

    public CustomAuthorizationServiceIntrospector(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (Objects.isNull(authorization) || authorization == null) {
            log.error("Invalid token: {}", token);
            throw new InvalidBearerTokenException("invalid_token: " + token);
        }

        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
            log.info("Client credentials grant type detected for token: {}", token);
            return new DefaultOAuth2AuthenticatedPrincipal(authorization.getPrincipalName()
                    , authorization.getAttributes(), AuthorityUtils.NO_AUTHORITIES);
        }

        String accountType = (String)authorization.getAttributes().get(SecurityConstants.ACCOUNT_TYPE_PARAM_NAME);
        Authentication authentication = (Authentication)authorization.getAttributes().get(Principal.class.getName());
        OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal)authentication.getPrincipal();

        principal.getAttributes().put(SecurityConstants.CLIENT_ID, authorization.getRegisteredClientId());
        principal.getAttributes().put(SecurityConstants.ACCOUNT_TYPE_PARAM_NAME, accountType);

        log.info("Introspected token for principal: {}, client_id: {}, account_type: {}"
                , principal.getName(), principal.getAttribute(SecurityConstants.CLIENT_ID)
                , principal.getAttribute(SecurityConstants.ACCOUNT_TYPE_PARAM_NAME));
        return principal;
    }
}
