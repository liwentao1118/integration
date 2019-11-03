package com.muzili.integration.jwt.model;

import lombok.Builder;

import java.util.HashMap;
import java.util.Map;

@Builder
public class JwtUser {

    private Long userId;

    private String userName;

    private JwtUserEnum userEnum;

    private String roles;

    private String userLoginCode;

    private Map<String, String> extInfos;

    public Map<String, String> getExtInfos() {
        return extInfos;
    }

    public void setExtInfos(Map<String, String> extInfos) {
        this.extInfos = extInfos;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserLoginCode() {
        return userLoginCode;
    }

    public void setUserLoginCode(String userLoginCode) {
        this.userLoginCode = userLoginCode;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public JwtUserEnum getUserType() {
        return userEnum;
    }

    public void setUserType(JwtUserEnum userType) {
        this.userEnum = userType;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public void putExtInfo(String key, String value) {
        if (extInfos == null) {
            extInfos = new HashMap<String, String>();
        }
        extInfos.put(key, value);
    }

    public String getExtInfo(String key) {
        if(extInfos == null) {
            return null;
        }

        return extInfos.get(key);
    }

}
