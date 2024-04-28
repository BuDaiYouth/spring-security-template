package xyz.ibudai.security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
@MapperScan("xyz.ibudai.security.common.dao")
@SpringBootApplication(scanBasePackages = "xyz.ibudai.security")
public class Security2Application {

    public static void main(String[] args) {
        SpringApplication.run(Security2Application.class, args);
    }
}
