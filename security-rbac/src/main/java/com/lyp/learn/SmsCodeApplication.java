package com.lyp.learn;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(basePackages = {"com.lyp.learn.dao"})
public class SmsCodeApplication {
    public static void main(String[] args) {
        SpringApplication.run(SmsCodeApplication.class, args);
    }

}
