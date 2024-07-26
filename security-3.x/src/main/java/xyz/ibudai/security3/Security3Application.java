package xyz.ibudai.security3;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity
@EnableConfigurationProperties
@MapperScan("xyz.ibudai.security.manager.dao")
@SpringBootApplication(scanBasePackages = {
        "xyz.ibudai.security3",
        "xyz.ibudai.security.common",
        "xyz.ibudai.security.manager",
})
public class Security3Application {

    public static void main(String[] args) {
        SpringApplication.run(Security3Application.class, args);
    }
}
