package com.example.auth_client_starter.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import lombok.Getter;

@Getter
public class PasswordCodeAuthenticationToken extends BaseAuthenticationToken{
    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("password_code");
    private final Object principal;
    private final String credentials;
    private final String validCode;
    private final String deviceId;

    public PasswordCodeAuthenticationToken(
        String username,
        String password,
        String validCode,
        String deviceId
    ){
        super(GRANT_TYPE);
        this.principal = username;
        this.credentials = password;
        this.validCode = validCode;
        this.deviceId = deviceId;
        super.setAuthenticated(true);
    }

    public PasswordCodeAuthenticationToken(
        UserDetails user,
        String password,
        String validCode,
        String deviceId,
        Collection<? extends GrantedAuthority> authorities
    ){
        super(authorities);
        this.principal = user;
        this.credentials = password;
        this.validCode = validCode;
        this.deviceId = deviceId;
    }
}
