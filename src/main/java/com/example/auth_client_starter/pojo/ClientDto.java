package com.example.auth_client_starter.pojo;

import java.io.Serial;
import java.io.Serializable;

import lombok.Data;

@Data
public class ClientDto implements Serializable{
    @Serial
    private static final long serialVersionUID = 1L;

    private String id;

    private String clientId;

    private String clientName;

    private String resourceIds;

    private String clientSecret;

    private String clientSecretStr;

    private String scope = "All";

    private String authorizedGrantTypes = "authorization_code,password,refresh_token,client_credentials";

    private String webServerRedirectUri;

    private Integer accessTokenValiditySeconds = 18000;
    
    private String authorities = "";

    private Integer refreshTokenValiditySeconds = 28800;

    private String additionalInformation = "{}";

    private String autoapprove = "true";

    private String tokenFormat = "reference";

    private Long creatorId;

}
