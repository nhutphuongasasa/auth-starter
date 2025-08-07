package com.example.auth_client_starter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;

@RefreshScope
@ConfigurationProperties(prefix = "secutiry")
public class SecurityProperties {
    private AuthProperties auth = new AuthProperties();

    private PermitProperties ignore = new PermitProperties();

    private ValidateCodeProperties code = new ValidateCodeProperties();

    private ResourceServerProperties resourceServer = new ResourceServerProperties();

    public AuthProperties getAuth() {
        return auth;
    }

    public void setAuth(AuthProperties auth) {
        this.auth = auth;
    }

    public PermitProperties getIgnore() {
        return ignore;
    }

    public void setIgnore(PermitProperties ignore) {
        this.ignore = ignore;
    }

    public ValidateCodeProperties getCode() {
        return code;
    }

    public void setCode(ValidateCodeProperties code) {
        this.code = code;
    }

    public ResourceServerProperties getResourceServer() {
        return resourceServer;
    }

    public void setResourceServer(ResourceServerProperties resourceServer) {
        this.resourceServer = resourceServer;
    }
}
