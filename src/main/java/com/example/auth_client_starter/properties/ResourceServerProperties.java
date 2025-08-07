package com.example.auth_client_starter.properties;

public class ResourceServerProperties {
    private String tokenType = "redis";

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}
