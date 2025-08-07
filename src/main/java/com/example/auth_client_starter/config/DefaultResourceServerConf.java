package com.example.auth_client_starter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
// import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.example.auth_client_starter.components.CustomAuthorizationServiceIntrospector;
import com.example.auth_client_starter.components.CustomBearerTokenResolver;
import com.example.auth_client_starter.enums.TokenType;
import com.example.auth_client_starter.properties.SecurityProperties;

@EnableWebSecurity
@Import(BaseSecurityConfig.class)
public class DefaultResourceServerConf {
    private final SecurityProperties securityProperties;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final CustomBearerTokenResolver customBearerTokenResolver;
    private final AccessDeniedHandler accessDeniedHandler;
    //lay tu context (xem lai )
    @Autowired
    private OAuth2AuthorizationService auth2AuthorizationService;
    
    public DefaultResourceServerConf(
        SecurityProperties securityProperties,
        AuthenticationEntryPoint authenticationEntryPoint,
        CustomBearerTokenResolver customBearerTokenResolver,
        AccessDeniedHandler accessDeniedHandler
    ){
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.customBearerTokenResolver = customBearerTokenResolver;
        this.securityProperties = securityProperties;
    }

    protected OpaqueTokenIntrospector getOpaqueTokenIntrospector(){
        return new CustomAuthorizationServiceIntrospector(auth2AuthorizationService);
    }

    protected void setAuthenticate(
        AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl authorizedUrl
    ){
        authorizedUrl.authenticated();
    }

    //filter
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
        HttpSecurity http
    ) throws Exception{
        http.authorizeHttpRequests(authorizeRequests -> {
            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl aithorizedUrl = authorizeRequests
                    .requestMatchers(HttpMethod.OPTIONS).permitAll()
                    .requestMatchers(securityProperties.getIgnore().getUrl()).permitAll()
                    .anyRequest();
            
            this.setAuthenticate(aithorizedUrl);
        }).headers(header -> {
            header.frameOptions(HeadersConfigurer.FrameOptionsConfig :: sameOrigin);
        }).csrf(AbstractHttpConfigurer :: disable)
            .cors(AbstractHttpConfigurer :: disable)
            .sessionManagement(session -> {
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        });

        //cau hinh resource server
        http.oauth2ResourceServer(oauth2 -> {
            oauth2.authenticationEntryPoint(authenticationEntryPoint)
                .bearerTokenResolver(customBearerTokenResolver)
                .accessDeniedHandler(accessDeniedHandler);

            if(TokenType.JWT.getName().equals(securityProperties.getResourceServer().getTokenType())){
                oauth2.jwt(Customizer.withDefaults());
            } else{
                oauth2.opaqueToken(token -> token.introspector(this.getOpaqueTokenIntrospector()));            }
        });

        return http.build();
    }

}
