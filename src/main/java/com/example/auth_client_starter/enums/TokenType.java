package com.example.auth_client_starter.enums;


public enum TokenType {
    REDIS("redis"),
    MEMORY("inMemory"),
    JWT("jwt"),
    REF("reference");
    
    private final String name;

    TokenType(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

}
