package com.example.auth_client_starter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.example.auth_client_starter.properties.SecurityProperties;

@EnableConfigurationProperties({SecurityProperties.class})
@SpringBootApplication
public class AuthClientStarterApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthClientStarterApplication.class, args);
	}

}
