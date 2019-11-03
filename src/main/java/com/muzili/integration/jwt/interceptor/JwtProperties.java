package com.muzili.integration.jwt.interceptor;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String jwtWhiteList;

    private String jwtSecretKey;

    public String getJwtWhiteList() {
        return jwtWhiteList;
    }

    public void setJwtWhiteList(String jwtWhiteList) {
        this.jwtWhiteList = jwtWhiteList;
    }

    public String getJwtSecretKey() {
        return jwtSecretKey;
    }

    public void setJwtSecretKey(String jwtSecretKey) {
        this.jwtSecretKey = jwtSecretKey;
    }
}
