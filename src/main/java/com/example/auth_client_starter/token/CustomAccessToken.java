package com.example.auth_client_starter.token;

import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

public class CustomAccessToken extends OAuth2Authorization.Token<OAuth2Token>{
    public CustomAccessToken(
        OAuth2AccessToken accessToken,
        Map metadata
    ){
        super(accessToken, metadata);
    }
}
