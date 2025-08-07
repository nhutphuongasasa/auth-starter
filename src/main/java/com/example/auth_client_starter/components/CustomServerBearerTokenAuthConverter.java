package com.example.auth_client_starter.components;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.example.auth_client_starter.properties.PermitProperties;
import com.example.auth_client_starter.properties.SecurityProperties;

import reactor.core.publisher.Mono;

public class CustomServerBearerTokenAuthConverter implements ServerAuthenticationConverter{
    private final PathMatcher pathMatcher = new AntPathMatcher();

    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
        Pattern.CASE_INSENSITIVE);

    private boolean allowUriQueryParameter = false;

    private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

    private final PermitProperties permitProperties;

    public CustomServerBearerTokenAuthConverter(
        SecurityProperties securityProperties
    ){
        this.permitProperties = securityProperties.getIgnore();
    }

    public String resolveFromAuthorizationHeader(HttpHeaders headers){
        //lay token
        String authorization = headers.getFirst(this.bearerTokenHeaderName);

        if(!StringUtils.startsWithIgnoreCase(authorization, "Bearer")){
            return null;
        }

        //regex kiem tra 
        Matcher matcher = authorizationPattern.matcher(authorization);
        
        if(!matcher.matches()){
            BearerTokenError error = invalidTokenError();
            throw new OAuth2AuthenticationException(error);
        }
        //tra ve chuoi vi du "Bearer abc123.xyz456" -> "abc123.xyz456"
        return matcher.group("token");
    }

    public String resolveAccessTokenFromRequest(ServerHttpRequest request){
        List<String> parameterTokens = request.getQueryParams().get("access_token");

        if(CollectionUtils.isEmpty(parameterTokens)){
            return null;
        }

        if (parameterTokens.size() == 1) {
            return parameterTokens.get(0);
        }

        BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
        throw new OAuth2AuthenticationException(error);
    }

    public String token(ServerHttpRequest request){
        boolean match = Arrays.stream(permitProperties.getUrl())
            .anyMatch(url -> pathMatcher.match(url, request.getURI().getPath()));

        if(match){
            return null;
        }

        String authorizationHeaderToken = resolveFromAuthorizationHeader(request.getHeaders());

        String parameterToken = resolveAccessTokenFromRequest(request);

        if(authorizationHeaderToken != null){
            if(parameterToken != null){
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            }
        }
        
        if(parameterToken != null){
            return parameterToken;
        }

        return null;
    }

    public static BearerTokenError invalidTokenError(){
        return BearerTokenErrors.invalidToken("Bearer token is malformed");
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> token(exchange.getRequest())).map(token -> {
            if(token.isEmpty()){
                BearerTokenError error = invalidTokenError();
                throw new OAuth2AuthenticationException(error);
            }

            return new BearerTokenAuthenticationToken(token);
        });
    }

    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }
    
    public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
        this.bearerTokenHeaderName = bearerTokenHeaderName;
    }

    private boolean isParameterTokenSupportedForRequest(ServerHttpRequest request) {
        return this.allowUriQueryParameter && HttpMethod.GET.equals(request.getMethod());
    }
}
