package com.example.auth_client_starter.config;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.example.auth_client_starter.utils.AuthUtils;

import jakarta.websocket.server.ServerEndpointConfig;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class WcAuthConfigurator extends ServerEndpointConfig.Configurator{
    private AuthUtils authUtils;

    @Override
    public boolean checkOrigin(String originHeaderValue) {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();

        if(servletRequestAttributes == null){
            log.error("WebSocket authentication failed", "RequestAttributes is null");
            return false;
        }

        try {
            authUtils.checkAccessToken(servletRequestAttributes.getRequest());
        } catch (Exception e) {
            log.error("WebSocket authentication failed", e);
            return false;
        }

        return super.checkOrigin(originHeaderValue);
    }
}
