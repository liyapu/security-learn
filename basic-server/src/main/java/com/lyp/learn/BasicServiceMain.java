package com.lyp.learn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 *  字母哥
 *    https://gitee.com/hanxt/dongbb
 *
 *  基于字母哥课堂的spring-security,把每个章节的功能独立出来
 *  https://github.com/Nagisaki/my-spring-security-demo
 *
 */
//@SpringBootApplication
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class BasicServiceMain {
    public static void main(String[] args) {
        SpringApplication.run(BasicServiceMain.class, args);
    }
}
