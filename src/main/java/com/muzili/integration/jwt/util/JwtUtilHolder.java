package com.muzili.integration.jwt.util;

import com.muzili.integration.jwt.model.AtomicFinalObject;
import org.springframework.util.Assert;

public class JwtUtilHolder {

    private static AtomicFinalObject<JwtUtil> holder = new AtomicFinalObject<>();

    public static boolean init (String key){
        JwtUtil jwtUtil = holder.getValue();
        if (jwtUtil == null){
            holder.setValue(JwtUtil.getInstance(key));
            return true;
        }
        return false;
    }

    public static boolean init (JwtUtil jwtUtil){
        JwtUtil inst = holder.getValue();
        if (inst == null){
            holder.setValue(jwtUtil);
            return true;
        }
        return false;
    }

    public static JwtUtil getJWTUtil() {
        JwtUtil jwtUtil = holder.getValue();
        Assert.notNull(jwtUtil, "JWTUtilHolder 未初始化");
        return jwtUtil;
    }



}
