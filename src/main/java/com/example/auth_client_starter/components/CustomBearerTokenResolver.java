package com.example.auth_client_starter.components;

import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import com.example.auth_client_starter.properties.PermitProperties;
import com.example.auth_client_starter.properties.SecurityProperties;
import com.example.auth_client_starter.utils.AuthUtils;

import jakarta.servlet.http.HttpServletRequest;

@ConditionalOnClass(HttpServletRequest.class)
@Component
public class CustomBearerTokenResolver implements BearerTokenResolver{
    private boolean allowFormEncodedBodyParameter = false;

    private final boolean allowUriQueryParameter = true;

    // private final String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

    private final PathMatcher pathMatcher = new AntPathMatcher();

    private final PermitProperties permitProperties;

    public CustomBearerTokenResolver(
        SecurityProperties securityProperties
    ) {
        this.permitProperties = securityProperties.getIgnore();
    }

    private boolean isParameterTokenSupportedForRequest(
        HttpServletRequest request
    ){
        return (("POST").equals(request.getMethod()))
            && MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType())//kiem tra xen co post qua form hay khong
            || "GET".equals(request.getMethod());
    }

    private static String resolveFromRequestParameters(
        HttpServletRequest request
    ){
        String[] values = request.getParameterValues("access_token");

        if(values == null || values.length == 0){
            return null;
        }

        if(values.length == 1){
            return values[0];
        }

        BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
        throw new OAuth2AuthenticationException(error);
    }

    public boolean isParameterTokenEnabledForRequest(
        HttpServletRequest request
    ){
        return ((this.allowFormEncodedBodyParameter && "POST".equals(request.getMethod())
            && MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType()))
            || (this.allowUriQueryParameter && "GET".equals(request.getMethod())));
    }

    @Override
    public String resolve(HttpServletRequest request) {
        Boolean match = Arrays.stream(permitProperties.getUrl())
            .anyMatch(url -> pathMatcher.match(url, request.getRequestURI()));

        if(match){
            return null;
        }

        final String authorizationHeaderToken = AuthUtils.extraToken(request);

        final String parameterToken = isParameterTokenSupportedForRequest(request)
                ? resolveFromRequestParameters(request) : null;

        if(authorizationHeaderToken != null){
            if(parameterToken != null){
                final BearerTokenError error = BearerTokenErrors
                    .invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            }

            return authorizationHeaderToken;
        }

        if(parameterToken != null && isParameterTokenSupportedForRequest(request)){
            return parameterToken;
        }

        return null;
    }

    public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
        this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
    }
}
