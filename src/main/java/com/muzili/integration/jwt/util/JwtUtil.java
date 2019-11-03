package com.muzili.integration.jwt.util;


import com.muzili.integration.jwt.exception.JwtVerifyException;
import com.muzili.integration.jwt.model.JwtUser;
import com.muzili.integration.jwt.model.JwtUserEnum;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import net.minidev.json.JSONObject;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.text.ParseException;
import java.util.Map;

public class JwtUtil {

    private static String USER_ID = "_user_id";

    private static String USER_NAME = "_user_name";

    private static String USER_ROLES = "_user_role";

    private static String USER_TYPE = "_user_type";

    private static String USER_LOGIN_CODE = "_user_login_code";

    private static String KEY_EXP = "exp";

    private static String KEY = "xUjhQxMuwoE+KpbqWH7DNVU1AMBHeg7VjuKo0ZJnSqI=";

    private String key;
    private byte[] _sharedKey;

    public static byte[] shareKey;

    static {
        shareKey = new byte[32];
        //将字符串转换成字节流
        shareKey = Base64Utils.decode(KEY);
    }

    public static String getDefaultKey(){
        return KEY;
    }

    public static JwtUtil getInstance_(){
        return getInstance(KEY);
    }

    public static JwtUtil getInstance (String key){
        JwtUtil instance = new JwtUtil();
        instance.key = key;
        instance._sharedKey = new byte[32];
        instance._sharedKey = Base64Utils.decode(key);
        return instance;
    }

    public String _sign(JSONObject json , long liveTime){
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        if (liveTime > 0){
            json.put(KEY_EXP,System.currentTimeMillis() + liveTime);
        }

        Payload payload = new Payload(json);
        JWSObject jwsObject = new JWSObject(header, payload);
        try {
            jwsObject.sign(new MACSigner(this._sharedKey));
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        String jwt = jwsObject.serialize();

        return jwt;
    }

    public String signJwtUser (JwtUser user , long liveTime){
        Assert.notNull(user);
        Assert.notNull(user.getRoles());
        Assert.notNull(user.getUserId());
        Assert.notNull(user.getUserType());

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(USER_ID, user.getUserId());
        jsonObject.put(USER_NAME, user.getUserName());
        jsonObject.put(USER_ROLES, user.getRoles());
        jsonObject.put(USER_TYPE, user.getUserType().getName());
        jsonObject.put(USER_LOGIN_CODE, user.getUserLoginCode());

        Map<String, String> extInfos = user.getExtInfos();
        if(extInfos != null && extInfos.size() > 0) {
            for(String key : extInfos.keySet()) {
                jsonObject.put(key, extInfos.get(key));
            }
        }
        return _sign(jsonObject, liveTime);
    }

    public String signJwtUser(JwtUser user) {
        return signJwtUser(user,2*60*60*1000L);
    }

    public JwtUser getJwtUserByJwt(String jwt){
        JWTVerifyResult result = _verify(jwt, true);
        if (result.result != JWTVerifyEnum.SUCCESS){
            return null;
        }

        JSONObject payload = result.getPayload();

        if(!payload.containsKey(USER_ID)) {
            return null;
        }
        if(!payload.containsKey(USER_ROLES)) {
            return null;
        }
        if(!payload.containsKey(USER_TYPE)) {
            return null;
        }
        JwtUser jwtUser = JwtUser.builder().userId(payload.getAsNumber(USER_ID).longValue())
                .roles(payload.getAsString(USER_ROLES))
                .userEnum(JwtUserEnum.resolve(payload.getAsString(USER_TYPE))).build();
        if (payload.containsKey(USER_LOGIN_CODE)){
            jwtUser.setUserLoginCode(payload.getAsString(USER_LOGIN_CODE));
        }

        if(payload.containsKey(USER_NAME)) {
            jwtUser.setUserName(payload.getAsString(USER_NAME));
        }

        for(String key : payload.keySet()) {
            if(USER_ID.equals(key)) {
                continue;
            }
            if(USER_NAME.equals(key)) {
                continue;
            }
            if(USER_ROLES.equals(key)) {
                continue;
            }
            if(USER_TYPE.equals(key)) {
                continue;
            }
            if(USER_LOGIN_CODE.equals(key)) {
                continue;
            }

            jwtUser.putExtInfo(key, payload.getAsString(key));
        }

       return jwtUser;
    }

    public static String fetchKeyByRequestHeader(HttpServletRequest request) {
        if(!verifyRequestHeader(request)){
            throw new JwtVerifyException("没有传入标准的JWT方式（header/Authorization/Bearer 等等）");
        }

        return request.getHeader("Authorization").substring("Bearer ".length());
    }


    public static boolean verifyRequestHeader(HttpServletRequest request){
        String authorization = request.getHeader("Authorization");
        if (authorization == null){
            return false;
        }

        if (!authorization.startsWith("Bearer ")){
            return false;
        }

        return true;
    }

    public JWTVerifyResult _verify(String jwt,boolean mustHaveExp){
        JWSObject jwsObject = parse(jwt);
        if (jwsObject == null){
            return JWTVerifyResult.fail();
        }

        Payload payload = jwsObject.getPayload();

        if (payload == null){
            return JWTVerifyResult.fail();
        }

        JSONObject jsonObject = payload.toJSONObject();

        if (mustHaveExp){
            if (!jsonObject.containsKey(KEY_EXP)){
                return JWTVerifyResult.fail("jwt token 必须含有exp属性");
            }
        }

        if (jsonObject != null && jsonObject.containsKey(KEY_EXP)){
            if (jsonObject.getAsNumber(KEY_EXP).longValue() < System.currentTimeMillis()){
                return JWTVerifyResult.exp();
            }
        }

        JWSVerifier jwsVerifier = null;

        try {
            jwsVerifier = new MACVerifier(this._sharedKey);
        } catch (JOSEException e) {
            e.printStackTrace();
            return JWTVerifyResult.fail();
        }

        try {
            boolean verify = jwsObject.verify(jwsVerifier);

            if (verify){
                JWTVerifyResult result = JWTVerifyResult.success();
                result.setPayload(jsonObject);
                return result;
            }else {
                return JWTVerifyResult.fail();
            }
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return JWTVerifyResult.fail();
    }

    public JWSObject parse(String jwt){
        if (jwt == null){
            return null;
        }
        try {
            return JWSObject.parse(jwt);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }



    public static class JWTVerifyResult implements Serializable {
        private static final long serialVersionUID = -6990128954601706499L;

        private JWTVerifyEnum result;
        private int code;
        private String message;
        private JSONObject payload;

        public JSONObject getPayload() {
            return payload;
        }
        public void setPayload(JSONObject payload) {
            this.payload = payload;
        }
        public JWTVerifyEnum getResult() {
            return result;
        }
        public void setResult(JWTVerifyEnum result) {
            this.result = result;
        }
        public int getCode() {
            return code;
        }
        public void setCode(int code) {
            this.code = code;
        }
        public String getMessage() {
            return message;
        }
        public void setMessage(String message) {
            this.message = message;
        }
        public static JWTVerifyResult fail() {
            return fail("验证失败");
        }
        public static JWTVerifyResult fail(String msg) {
            JWTVerifyResult result = new JWTVerifyResult();
            result.setCode(0);
            result.setResult(JWTVerifyEnum.FAIL);
            result.setMessage(msg);
            return result;
        }

        public static JWTVerifyResult exp() {
            JWTVerifyResult result = new JWTVerifyResult();
            result.setCode(0);
            result.setResult(JWTVerifyEnum.EXPIRED);
            result.setMessage("JWT过时");
            return result;
        }
        public static JWTVerifyResult success() {
            JWTVerifyResult result = new JWTVerifyResult();
            result.setCode(0);
            result.setResult(JWTVerifyEnum.SUCCESS);
            result.setMessage("验证成功");
            return result;
        }

    }

    public static enum JWTVerifyEnum implements Serializable {
        /** JWT验证成功 */
        SUCCESS(200),

        /** 签名错误 JWT */
        FAIL(601),

        //格式错误
        FORMAT_ERROR(803),
        /** JWT签名超时 */
        EXPIRED(801);



        private int httpResponseCode;

        private JWTVerifyEnum(int code) {
            httpResponseCode = code;
        }
        public int getHttpResponseCode() {
            return httpResponseCode;
        }
    }

    public static void main(String[] args) throws InterruptedException {

        JwtUser jwtUser = JwtUser.builder().userId(1L).roles("user")
                .userLoginCode("haha").userEnum(JwtUserEnum.WECHAT).build();
        jwtUser.putExtInfo("app_token", "abcd");

        String token = JwtUtil.getInstance(KEY).signJwtUser(jwtUser);
        System.out.println("token : "+token);
        JwtUser jwtUserByJWT = JwtUtil.getInstance(KEY).getJwtUserByJwt(token);
        System.out.println(jwtUserByJWT.getExtInfo("app_token"));
    }





}
