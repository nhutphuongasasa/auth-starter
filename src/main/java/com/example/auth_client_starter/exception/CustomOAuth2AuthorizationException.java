package com.example.auth_client_starter.exception;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public class CustomOAuth2AuthorizationException extends OAuth2AuthenticationException{
    public CustomOAuth2AuthorizationException(String msg){
        super(new OAuth2Error(msg), msg);
    }
}
