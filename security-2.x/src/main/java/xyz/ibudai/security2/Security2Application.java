package xyz.ibudai.security2;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableConfigurationProperties
@EnableWebSecurity(debug = true)
@MapperScan("xyz.ibudai.security.repository.dao")
@SpringBootApplication(scanBasePackages = {
        "xyz.ibudai.security2",
        "xyz.ibudai.security.api",
        "xyz.ibudai.security.core",
        "xyz.ibudai.security.repository",
})
public class Security2Application {

    public static void main(String[] args) {
        SpringApplication.run(Security2Application.class, args);
    }
}
