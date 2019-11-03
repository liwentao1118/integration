package com.muzili.integration.jwt.util;

import org.apache.commons.codec.binary.Base64;

public class Base64Utils {

    private final static Base64 BASE64 = new Base64();

    public static byte[] decode (String str){
        return BASE64.decode(str);
    }

}
