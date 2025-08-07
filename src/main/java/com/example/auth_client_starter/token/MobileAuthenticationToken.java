package com.example.auth_client_starter.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import lombok.Getter;

@Getter
public class MobileAuthenticationToken extends BaseAuthenticationToken{
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("mobile_password");
    public final Object principal;
    public final String credentials;

    public MobileAuthenticationToken(
        String mobile,
        String password
    ){
        super(GRANT_TYPE);
        this.principal = mobile;
        this.credentials = password;
        super.setAuthenticated(true);
    }

    public MobileAuthenticationToken(
        UserDetails user,
        String password,
        Collection<? extends GrantedAuthority> authorities
    ){
        super(authorities);
        this.principal = user;
        this.credentials = password;
        super.setAuthenticated(true);
    }
}