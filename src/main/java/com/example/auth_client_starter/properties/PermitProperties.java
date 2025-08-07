package com.example.auth_client_starter.properties;

import java.util.ArrayList;
import java.util.List;

import com.example.auth_client_starter.constants.SecurityConstants;


public class PermitProperties {
    public static String[] getEndpoints() {
        return ENDPOINTS;
    }

    public String[] getHttpUrls() {
        return httpUrls;
    }

    public void setHttpUrls(String[] httpUrls) {
        this.httpUrls = httpUrls;
    }

    private static final String[] ENDPOINTS = {
        SecurityConstants.LOGIN_PAGE,
        SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/**",
        "/doc.html", "/swagger-ui.html", "/v3/api-docs/**", "/swagger-ui/**",
        "/actuator/**", "/webjars/**", "/druid/**",
        "/css/**", "/js/**", "/images/**", "/favicon.ico", "/error"
    };

    private String[] httpUrls = {};

    public String[] getUrl(){
        if(httpUrls == null || httpUrls.length == 0){
            return ENDPOINTS;
        }

        List<String> list = new ArrayList<>();

        for (String url : ENDPOINTS) {
            list.add(url);
        }

        for(String url : httpUrls){
            list.add(url);
        }

        return list.toArray(new String[list.size()]);
    }
}
