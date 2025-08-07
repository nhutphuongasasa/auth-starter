package com.example.auth_client_starter.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class OpenIdAuthenticationToken extends BaseAuthenticationToken{
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("openid");
    
    public final Object principal;

    public OpenIdAuthenticationToken(
        String openId
    ){
        super(GRANT_TYPE);
        this.principal = openId;
        super.setAuthenticated(true);
    }

    public OpenIdAuthenticationToken(
        UserDetails principal,
        Collection<? extends GrantedAuthority> authorities
    ){
        super(authorities);
        this.principal = principal;
    }
}

