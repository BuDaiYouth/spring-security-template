package xyz.ibudai.security.api.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/open")
public class OpenController {

    @GetMapping("/hello")
    public String hello() {
        return "Open resource-1";
    }

    @GetMapping("/sec/hello")
    public String secHello() {
        return "Open resource-2";
    }
}
