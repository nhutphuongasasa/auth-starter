package com.example.auth_client_starter.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import lombok.Getter;

@Getter
public class PasswordAuthenticationToken extends BaseAuthenticationToken{
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("password");
    private final Object principal;
    private final String credentials;

    public PasswordAuthenticationToken(
        String username,
        String password
    ){
        super(GRANT_TYPE);
        this.principal = username;
        this.credentials = password;
        super.setAuthenticated(true);
    }

    public PasswordAuthenticationToken(
        UserDetails user,
        String password,
        Collection<? extends GrantedAuthority> authorities
    ){
        super(authorities);
        this.principal = user;
        this.credentials = password;
    }
}
