package com.example.auth_client_starter.token;

import java.io.Serial;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;

import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BaseAuthenticationToken extends AbstractAuthenticationToken{
    @Serial
    private static final Long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

    private final AuthorizationGrantType grantType;

    private Authentication clientPrincipal;

    private Map<String, Object> additionalParameters;

    private Set<String> scopes;

    public BaseAuthenticationToken(
        AuthorizationGrantType authorizationGrantType
    ){
        super(null);
        this.grantType = authorizationGrantType;
    }

    public BaseAuthenticationToken(
        AuthorizationGrantType authorizationGrantType,
        Set<String> scopes,
        Authentication clientPrincipal,
        @Nullable Map<String, Object> additionalParameters
    ){
        super(null);
        this.grantType = authorizationGrantType;
        this.scopes = Collections.unmodifiableSet(scopes != null ? scopes : Collections.emptySet());
        this.clientPrincipal =  clientPrincipal;
        this.additionalParameters = additionalParameters;
    }

    public BaseAuthenticationToken(Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        this.grantType = null;
        this.clientPrincipal = null;
        this.additionalParameters = null;
        this.scopes = null;
    }

    @Override
    public Object getPrincipal(){
        return this.clientPrincipal;
    }

    @Override
    public Object getCredentials(){
        return "";
    }
}
