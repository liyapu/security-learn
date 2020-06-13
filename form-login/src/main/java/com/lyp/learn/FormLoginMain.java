package com.lyp.learn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * @author: liyapu
 * @description:
 * @date 2020-06-13 13:00
 */
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class FormLoginMain {
    public static void main(String[] args) {
        SpringApplication.run(FormLoginMain.class,args);
    }
}
