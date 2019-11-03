package com.muzili.integration.jwt.model;

import java.io.Serializable;

public enum JwtUserEnum implements Serializable {

    USER("user"), WECHAT("wechat"), SHOP("shop"),APP_USER("app_user"),;

    private String name;

    private JwtUserEnum(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static JwtUserEnum resolve(String name) {
        for (JwtUserEnum ps : values()) {
            if (ps.name.equals(name)) {
                return ps;
            }
        }
        return null;
    }


}
