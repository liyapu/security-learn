package com.lyp.learn;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author: liyapu
 * @description:
 * @date 2020-06-14 09:39
 */
@MapperScan(basePackages = {"com.lyp.learn.dao"})
@SpringBootApplication
public class JwtMain {
    public static void main(String[] args) {
        SpringApplication.run(JwtMain.class,args);
    }
}
