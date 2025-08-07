package com.example.auth_client_starter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;

import com.example.auth_client_starter.components.CustomBearerTokenResolver;
import com.example.auth_client_starter.components.CustomReactiveAuthorizationServiceIntrospector;
import com.example.auth_client_starter.components.CustomServerBearerTokenAuthConverter;
import com.example.auth_client_starter.properties.SecurityProperties;

@EnableWebFluxSecurity
@Import(BaseSecurityConfig.class)
public class DefaultWebFluxResourceServerConf {
    private final SecurityProperties securityProperties;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final CustomBearerTokenResolver customBearerTokenResolver;
    private final AccessDeniedHandler accessDeniedHandler;
    private final ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;
    //lay tu context (xem lai )
    // @Autowired
    private final OAuth2AuthorizationService auth2AuthorizationService;

    private final ServerAccessDeniedHandler serverAccessDeniedHandler;

    @Autowired( required = false)
    private ReactiveAuthorizationManager authorizationManager;

    @Autowired( required = false)
    private ServerAuthenticationSuccessHandler successHandler;


    
    public DefaultWebFluxResourceServerConf(
        SecurityProperties securityProperties,
        AuthenticationEntryPoint authenticationEntryPoint,
        CustomBearerTokenResolver customBearerTokenResolver,
        AccessDeniedHandler accessDeniedHandler,
        ServerAccessDeniedHandler serverAccessDeniedHandler,    
        OAuth2AuthorizationService auth2AuthorizationService,
        ServerAuthenticationEntryPoint serverAuthenticationEntryPoint
    ){
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.customBearerTokenResolver = customBearerTokenResolver;
        this.securityProperties = securityProperties;
        this.serverAccessDeniedHandler = serverAccessDeniedHandler;
        this.auth2AuthorizationService = auth2AuthorizationService;
        this.serverAuthenticationEntryPoint = serverAuthenticationEntryPoint;
    }

    protected ReactiveOpaqueTokenIntrospector getOpaqueTokenIntrospector(){
        return new CustomReactiveAuthorizationServiceIntrospector();
    }
        
    // protected ReactiveAuthenticationManager getAuthenticationManager(){
    //     return new OpaqueTokenReactiveAuthenticationManager(
    //         new CustomReactiveAuthorizationServiceIntrospector()
    //     );
    // }

    protected ServerAuthenticationEntryPointFailureHandler getFailureHandler(){
        ServerAuthenticationEntryPointFailureHandler failureHandler = new ServerAuthenticationEntryPointFailureHandler(
            serverAuthenticationEntryPoint
        );

        failureHandler.setRethrowAuthenticationServiceException(false);
        return failureHandler;
    }

    protected ServerAuthenticationConverter getAuthenticationConverter(){
        CustomServerBearerTokenAuthConverter customServerBearerTokenAuthConverter = new CustomServerBearerTokenAuthConverter(
            securityProperties
        );

        customServerBearerTokenAuthConverter.setAllowUriQueryParameter(true);
        return customServerBearerTokenAuthConverter;
    }

    protected AuthenticationWebFilter getAuthenWebFilter(){
        AuthenticationWebFilter oauth2 = new AuthenticationWebFilter(
            new OpaqueTokenReactiveAuthenticationManager(this.getOpaqueTokenIntrospector())
        );

        oauth2.setServerAuthenticationConverter(this.getAuthenticationConverter());
        oauth2.setAuthenticationFailureHandler(this.getFailureHandler());

        if(successHandler != null){
            oauth2.setAuthenticationSuccessHandler(successHandler);
        }

        return oauth2;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http){
        http.csrf(ServerHttpSecurity.CsrfSpec :: disable)
            .cors(ServerHttpSecurity.CorsSpec :: disable)
            .headers(hSpec -> hSpec.frameOptions(ServerHttpSecurity.HeaderSpec.FrameOptionsSpec :: disable))
            .httpBasic(ServerHttpSecurity.HttpBasicSpec :: disable)
            .exceptionHandling(e -> {
                e.authenticationEntryPoint(serverAuthenticationEntryPoint)
                    .accessDeniedHandler(serverAccessDeniedHandler);  
            });

        http.authorizeExchange(exchange -> {
            if(securityProperties.getAuth().getHttpUrls().length > 0){
                exchange.pathMatchers(securityProperties.getAuth().getHttpUrls()).authenticated();
            }
            //bo qua xac thuc voi url nay
            if(securityProperties.getIgnore() != null){
                exchange.pathMatchers(HttpMethod.OPTIONS).permitAll();   
            }
            
            if(authorizationManager != null){
                exchange.anyExchange().access(authorizationManager);
            } else{
                exchange.anyExchange().authenticated();
            }
        });

        //them filter vao vi tri authentication
        http.addFilterAt(this.getAuthenWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION);
        
        return http.build();
    }
}
