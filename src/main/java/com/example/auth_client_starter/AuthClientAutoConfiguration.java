package com.example.auth_client_starter;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

import com.example.auth_client_starter.properties.SecurityProperties;

@EnableConfigurationProperties({SecurityProperties.class})
@ComponentScan
public class AuthClientAutoConfiguration {
    
}
