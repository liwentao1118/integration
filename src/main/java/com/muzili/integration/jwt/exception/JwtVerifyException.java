package com.muzili.integration.jwt.exception;

public class JwtVerifyException extends HttpStatusException {

    private static int statusCode = 601;

    public JwtVerifyException() {
        this("jwt验证失败");
    }

    public JwtVerifyException(String responseMessage) {
        super();
        setStatusCode(statusCode);
        setResponseMessage(responseMessage);
    }

}
