package com.muzili.integration.jwt;

import com.muzili.integration.jwt.interceptor.JwtProperties;
import com.muzili.integration.jwt.util.JwtUtil;
import com.muzili.integration.jwt.util.JwtUtilHolder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties(JwtProperties.class)
@Configuration
@Slf4j
public class JwtUtilConfiguration {

    @Autowired
    private JwtProperties jwtProperties;

    @Bean
    public JwtUtil jwtUtil(){
        log.info("初始化JWTUtilHolder");

        if (jwtProperties != null && StringUtils.isNotEmpty(jwtProperties.getJwtSecretKey())){
            JwtUtilHolder.init(jwtProperties.getJwtSecretKey());
        }else {
            JwtUtilHolder.init(JwtUtil.getInstance(JwtUtil.getDefaultKey()));
        }
        return JwtUtilHolder.getJWTUtil();
    }

}
