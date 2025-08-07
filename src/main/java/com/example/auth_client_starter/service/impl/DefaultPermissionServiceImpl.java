package com.example.auth_client_starter.service.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.example.auth_client_starter.constants.SecurityConstants;
import com.example.auth_client_starter.properties.SecurityProperties;
import com.example.common.constants.CommonConstant;
import com.example.common.context.TenantContextHolder;
import com.example.common.models.SysMenu;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class DefaultPermissionServiceImpl {
    @Autowired
    private SecurityProperties securityProperties;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public abstract List<SysMenu> findMenuByRoleCodes(String roleCodes);

    private boolean isNeedAuth(String clientId){
        boolean result = true;

        List<String> includeClientIds = securityProperties.getAuth().getUrlPermission().getIncludeClientIds();
        List<String> exclusiveClientIds = securityProperties.getAuth().getUrlPermission().getExclusiveClientIds();
        
        if(includeClientIds.size() > 0){
            result = includeClientIds.contains(clientId);
        } else if(exclusiveClientIds.size() > 0){
            result = !exclusiveClientIds.contains(clientId);
        }

        return result;
    }
    
    public boolean hasPermission(
        Authentication authentication,
        String requestMethod,
        String requestURI
    ){
        if(HttpMethod.OPTIONS.name().equalsIgnoreCase(requestMethod)){
            return true;
        }

        if(
            !(authentication instanceof AnonymousAuthenticationToken)
        ){
            if(!securityProperties.getAuth().getUrlPermission().getEnable()){
                return true;
            }

            OAuth2IntrospectionAuthenticatedPrincipal authenticationPrincipal = 
                (OAuth2IntrospectionAuthenticatedPrincipal) authentication.getPrincipal();

            String username = authentication.getName();

            if(CommonConstant.ADMIN_USER_NAME.equals(username)){
                return true;
            }

            Map<String, Object> claims = authenticationPrincipal.getAttributes();

            String clientId = (String)claims.get(SecurityConstants.CLIENT_ID);

            if(!isNeedAuth(clientId)){
                return true;
            }

            for(String path : securityProperties.getAuth().getUrlPermission().getIgnoreUrls()){
                if(antPathMatcher.match(path, requestURI)){
                    return true;
                }
            }

            Collection<SimpleGrantedAuthority> grantedAuthorityList =
                (Collection<SimpleGrantedAuthority>) authentication.getAuthorities();
            
            if(CollectionUtils.isEmpty(grantedAuthorityList)){
                log.warn("grantedAuthorities is empty", authentication.getPrincipal());
                return false;
            }

            TenantContextHolder.setTenant(clientId);

            String roleCodes = grantedAuthorityList.stream()
                .map(SimpleGrantedAuthority :: getAuthority)
                .collect(Collectors.joining(","));

            List<SysMenu> menuList = findMenuByRoleCodes(roleCodes);

            for(SysMenu menu : menuList){
                if(StringUtils.hasText(menu.getUrl()) && antPathMatcher.match(menu.getUrl(), requestURI)){
                    if(StringUtils.hasText(menu.getPathMethod())){
                        return requestMethod.equalsIgnoreCase(menu.getPathMethod());
                    } else{
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
