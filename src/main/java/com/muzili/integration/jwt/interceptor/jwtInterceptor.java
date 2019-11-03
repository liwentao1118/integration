package com.muzili.integration.jwt.interceptor;

import com.alibaba.fastjson.JSON;
import com.muzili.integration.jwt.model.JwtUser;
import com.muzili.integration.jwt.util.JwtUtil;
import com.muzili.integration.jwt.util.JwtUtilHolder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
@EnableConfigurationProperties(JwtProperties.class)
public class jwtInterceptor extends HandlerInterceptorAdapter {

    @Autowired
    private  JwtProperties jwtProperties;

    //APP 801状态码
    public static final Integer APP_SGIN_ERROR = 801; // 签名错误
    public static final Integer APP_SGIN_ERROR_JWT = 802; // 签名错误 JWT

    public static final Integer Format_Error = 803;  //格式错误

    //APP 701状态码
    public static final Integer APP_NO_PRI_ERROR = 701; // 无权限

    //APP 601状态码
    public static final Integer APP_EXPIRED_JWT = 601; // 超时 JWT过期

    private static final String START_TAG = "__start_time";



    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String reqPath = request.getServletPath();

        //过滤登录请求
        if (reqPath.matches("/user/wxLoginAuth")){
            return true;
        }

        if (reqPath.matches("/user/login.do")){
            return true;
        }

        //过滤白名单请求

        if(jwtProperties != null && StringUtils.isNotBlank(jwtProperties.getJwtWhiteList())) {

            String[] list = jwtProperties.getJwtWhiteList().split(",");

            if(list != null && list.length > 0) {
                for (String name : list) {
                    if (reqPath.matches(name)){
                        return true;
                    }
                }
            }
        }

        request.setAttribute(START_TAG,System.currentTimeMillis());

        //过滤options请求
        String method = request.getMethod();
        if ("OPTIONS".equalsIgnoreCase(method)){
            return true;
        }
        String jwtToken = null;
        if (JwtUtil.verifyRequestHeader(request)){
            jwtToken = JwtUtil.fetchKeyByRequestHeader(request);
            JwtUtil.JWTVerifyResult verify = JwtUtilHolder.getJWTUtil()._verify(jwtToken, true);
            if(verify.getResult() == JwtUtil.JWTVerifyEnum.EXPIRED) {
                log.info("repsonse status JWT EXPIRED [{}] ,request uri [{}]" , APP_EXPIRED_JWT, reqPath);
                response.setStatus(APP_EXPIRED_JWT);
                return false;
            }
            if(verify.getResult() == JwtUtil.JWTVerifyEnum.FAIL) {
                log.info("repsonse status JWT FAIL [{}] , request uri [{}] ", APP_SGIN_ERROR_JWT, reqPath);
                response.setStatus(APP_SGIN_ERROR_JWT);
                return false;
            }


            if(verify.getResult() == JwtUtil.JWTVerifyEnum.FORMAT_ERROR) {
                log.info("repsonse status JWT FAIL [{}] , request uri [{}] " , Format_Error, reqPath);
                response.setStatus(Format_Error);
                return false;
            }

        }else {
            log.info("repsonse status (headerHasBearer): " + APP_SGIN_ERROR);
            response.setStatus(APP_SGIN_ERROR);
            return false;
        }

        JwtUser jwtUser = JwtUtilHolder.getJWTUtil().getJwtUserByJwt(jwtToken);

        printForOther(request, jwtUser);
        return super.preHandle(request, response, handler);
    }

    private void printForOther(HttpServletRequest request, JwtUser jwtUser) {
        StringBuilder sb = new StringBuilder();
        sb.append("调用url: ").append(request.getRequestURI());
        sb.append(", 账号ID=").append(jwtUser.getUserId());
        sb.append(", 登录账号=").append(jwtUser.getUserLoginCode());
        sb.append(", jwt账号类型=").append(jwtUser.getUserType());
        sb.append(", 姓名=").append(jwtUser.getUserName());
        sb.append(", User-Agent=").append(request.getHeader("User-Agent"));
        sb.append(", Accept-Encoding=").append(request.getHeader("Accept-Encoding"));
        sb.append(", Content-Encoding=").append(request.getHeader("Content-Encoding"));
        sb.append(", request URL=").append(request.getRequestURL());
        sb.append(", http method=").append(request.getMethod());
        sb.append(", Host=").append(request.getHeader("Host"));
        sb.append(", Nginx-Access-Protocol=").append(request.getHeader("Nginx-Access-Protocol"));
        //sb.append(", IP=").append(IPUtils.fetchRealIPv4Addr(request));
        if(request.getParameterMap() != null) {
            sb.append(", ParameterMaps="+JSON.toJSONString(request.getParameterMap()));
        }

        log.info(sb.toString());
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        super.postHandle(request, response, handler, modelAndView);
    }
}
