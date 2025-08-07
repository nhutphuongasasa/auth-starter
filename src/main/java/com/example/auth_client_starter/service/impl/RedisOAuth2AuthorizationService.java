package com.example.auth_client_starter.service.impl;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.redisson.api.ExpiredObjectListener;
import org.redisson.api.RBucket;
import org.redisson.api.RList;
import org.redisson.api.RedissonClient;
import org.redisson.codec.SerializationCodec;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

// import com.example.auth_client_starter.common.constants.SecurityConstants;
import com.example.auth_client_starter.properties.SecurityProperties;
import com.example.common.constants.SecurityConstants;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService{
    private final static SerializationCodec AUTH_CODEC = new SerializationCodec();

    private final static Long STATE_TIMEOUT_MINUTES = 10L;

    private final String AUTHORIZATION = "token";

    private final SecurityProperties securityProperties;

    private final RedissonClient redisson;

    public RedisOAuth2AuthorizationService(
        SecurityProperties securityProperties,
        RedissonClient redisson
    ){
        this.redisson = redisson;
        this.securityProperties = securityProperties;
    }

    private RList<String> redisListDelete(
        String key,
        String value
    ){
        RList<String> rList = redisson.getList(key);
        rList.remove(value);
        return  rList;
    }

    private String buildKey(String type, String id) {
        return String.format("%s::%s::%s", AUTHORIZATION, type, id);
    }

    private final ExpiredObjectListener expiredObjectListener = new ExpiredObjectListener() {
        private final static String KEY_SPLIT = "::";

        @Override
        public void onExpired(String name){
            String[] keyArr = name.split(KEY_SPLIT);
            String clientId = keyArr[2];
            String username = keyArr[3];
            String accessToken = keyArr[4];

            redisListDelete(buildKey(
                SecurityConstants.REDIS_CLIENT_ID_TO_ACCESS,
                clientId
            ), accessToken);

            redisListDelete(buildKey(
                SecurityConstants.REDIS_UNAME_TO_ACCESS,
                username
            ), accessToken);
        }
    };

    private RBucket<OAuth2Authorization> redisBucketSet(
        String type,
        String id,
        OAuth2Authorization value,
        Duration duration
    ){
        RBucket<OAuth2Authorization> rBucket = redisson.getBucket(buildKey(type, id), AUTH_CODEC);
        rBucket.set(value, duration);
        return  rBucket;
    }

    //lay thoi gian song cua to0ken
    private Duration getExpireSeconds(OAuth2Token oAuth2Token){
        return Duration.ofSeconds(
            ChronoUnit.SECONDS.between(oAuth2Token.getIssuedAt(), oAuth2Token.getExpiresAt())
        );
    }

    private String buildListenerKey(String type, String clientId, String username, String tokenValue) {
        return String.format("%s::%s::%s::%s::%s", AUTHORIZATION, type, clientId, username, tokenValue);
    }

    private Duration saveAccessToken(OAuth2Authorization authorization, boolean isRenew){
        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        Duration duration = this.getExpireSeconds(accessToken);

        this.redisBucketSet(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue(), authorization, duration);

        RBucket<Integer> listenKeyBucket = redisson.getBucket(
            buildListenerKey(OAuth2ParameterNames.ACCESS_TOKEN, 
                authorization.getRegisteredClientId(),
                authorization.getPrincipalName(), 
                accessToken.getTokenValue()
            )
        );

        if(!isRenew){
            listenKeyBucket.set(1, duration);
            listenKeyBucket.addListener(expiredObjectListener);
        } else{
            listenKeyBucket.expire(duration);
        }

        return duration;
    }

    private RList<String> redisListAdd(String key, String value, Duration duration){
        RList<String> rList = redisson.getList(key);
        rList.add(value);
        rList.expire(duration);
        return rList;
    }

    public void save(OAuth2Authorization authorization){
        if(Objects.isNull(authorization.getAttribute("state"))){
            String token = authorization.getAttribute("state");
            this.redisBucketSet(OAuth2ParameterNames.STATE, token, authorization, Duration.ofMinutes(STATE_TIMEOUT_MINUTES));
        }

        if(Objects.nonNull(
            authorization.getToken(
                OAuth2AuthorizationCode.class
            )
        )){
            OAuth2AuthorizationCode authorizationCode = authorization.getToken(
                OAuth2AuthorizationCode.class
            ).getToken();
            Duration duration = this.getExpireSeconds(authorizationCode);
            this.redisBucketSet(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue(), authorization, duration);
        }

        if(Objects.nonNull(authorization.getRefreshToken())){
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();

            Duration duration = this.getExpireSeconds(refreshToken);

            this.redisBucketSet(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken.getTokenValue(), authorization, duration);
        }

        if(Objects.nonNull(authorization.getAccessToken())){
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            Duration duration = this.saveAccessToken(authorization, false);

            this.redisListAdd(
                buildKey(SecurityConstants.REDIS_CLIENT_ID_TO_ACCESS, authorization.getRegisteredClientId()),
                accessToken.getTokenValue(),
                duration
            );

            this.redisListAdd(
                buildKey(SecurityConstants.REDIS_CLIENT_ID_TO_ACCESS, authorization.getRegisteredClientId() + "::" + authorization.getPrincipalName()),
                accessToken.getTokenValue(),
                duration
            );
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization){
        Assert.notNull(authorization, "Authorization can not be null");

        List<String> keys = new ArrayList<>();
        if(Objects.nonNull(authorization.getAttribute("state"))){
            String token = authorization.getAttribute("state");
            keys.add(buildKey(OAuth2ParameterNames.STATE, token));
        }
        //kiem tra ma uy quyen
        if(Objects.nonNull(
            authorization.getToken(OAuth2AuthorizationCode.class)
        )){
            OAuth2AuthorizationCode authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class).getToken();
            keys.add(buildKey(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue()));
        }

        if(Objects.nonNull(
            authorization.getRefreshToken()
        )){
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
            keys.add(buildKey(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken.getTokenValue()));
        }

        if(Objects.nonNull(
            authorization.getAccessToken()
        )){
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            keys.add(buildKey(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue()));
        }

        redisson.getKeys().delete((String[]) keys.toArray(new String[0]));

        redisListDelete(buildKey(SecurityConstants.REDIS_CLIENT_ID_TO_ACCESS, authorization.getRegisteredClientId()), authorization.getId());
        redisListDelete(buildKey(SecurityConstants.REDIS_UNAME_TO_ACCESS, authorization.getRegisteredClientId() + "::" + authorization.getPrincipalName()), authorization.getId());
    }

    @Override
    @Nullable
    public OAuth2Authorization findById(String id){
        return this.findByToken(id, OAuth2TokenType.ACCESS_TOKEN);
    }

    @Override
    @Nullable
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType){
        Assert.hasText(token, "Token cannot be null");
        if(tokenType == null){
            tokenType = OAuth2TokenType.ACCESS_TOKEN;
        }

        OAuth2Authorization authorization = (OAuth2Authorization)redisson.getBucket(
            buildKey(tokenType.getValue(), token
        ), AUTH_CODEC).get();

        // Nếu bật tính năng gia hạn token và token là access token, kiểm tra gia hạn.
        boolean isRenew = securityProperties.getAuth().getRenew().getEnable();
        if (isRenew && tokenType.equals(OAuth2TokenType.ACCESS_TOKEN) && authorization != null) {
            this.renew(authorization);
        }

        return authorization;
    }

    public void renew(OAuth2Authorization authorization){
        
    }
}
