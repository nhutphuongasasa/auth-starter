package com.example.auth_client_starter.utils;

import java.security.Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

// import com.example.auth_client_starter.common.models.LoginAppUser;
// import com.example.auth_client_starter.common.utils.LoginUserUtils;
import com.example.auth_client_starter.constants.CommonConstants;
import com.example.common.models.LoginAppUser;
import com.example.common.utils.LoginUserUtils;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class AuthUtils{
    private static final Logger log = LoggerFactory.getLogger(AuthUtils.class);

    private final OAuth2AuthorizationService authorizationService;

    public AuthUtils(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    private static final String BASIC_ = "Basic ";

    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-:._~+/]+=*)$",
        Pattern.CASE_INSENSITIVE);

    public static String extraToken(HttpServletRequest request){
        String token = extraHeaderToken(request);

        if(token == null){
            token = request.getParameter(OAuth2ParameterNames.ACCESS_TOKEN);

            if(token == null){
                log.debug("Token not found in request parameters.  Not an OAuth2 request.");
            }
        }

        return token;
    }

    public static String extraHeaderToken(HttpServletRequest request){
        String authorization = request.getHeader(CommonConstants.TOKEN_HEADER);

        if(!StringUtils.startsWithIgnoreCase(authorization, "bearer ")){
            return null;
        }

        Matcher matcher = authorizationPattern.matcher(authorization);

        if(matcher.matches()){
            return matcher.group("token"); //tra ve token tu nhom token
        }

        return null;
    }

    public LoginAppUser checkAccessToken(HttpServletRequest request){
        String accessToken = extraToken(request);

        OAuth2Authorization authorization = checkAccessTokenToAuth(accessToken);
        
        Authentication authentication = (Authentication) authorization.getAttributes().get(Principal.class.getName());

        if(authentication == null){
            throw new OAuth2IntrospectionException("Invalid access token" + accessToken);
        }

        return LoginUserUtils.setContext(authentication);
    }

    public OAuth2Authorization checkAccessTokenToAuth(String token){
        if(token == null){
            throw new OAuth2IntrospectionException("Invalid access token: " + null);
        }
        //chua tat ca cac thong tin cua phien xac thuc oauth2
        OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if(authorization == null || authorization.getAccessToken() == null){
            throw new OAuth2IntrospectionException("Invalid access token: " + token);
        } else if(authorization.getAccessToken().isExpired()){
            authorizationService.remove(authorization);
            throw new OAuth2IntrospectionException("Access token expired: " + token);
        }

        return authorization;
    }
}