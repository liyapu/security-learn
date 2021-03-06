package com.lyp.learn.config.auth.smscode;

import java.time.LocalDateTime;

/**
 * 短信验证码 类
 */
public class SmsCode {

    private String code; //短信验证码

    private LocalDateTime expireTime; //过期时间

    private String mobile;


    public SmsCode(String code, int expireAfterSeconds, String mobile){
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
        this.mobile = mobile;
    }

    /**
     * 验证码是否过期
     * @return
     */
    public boolean isExpired(){
        return  LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode() {
        return code;
    }

    public String getMobile() {
        return mobile;
    }
}
