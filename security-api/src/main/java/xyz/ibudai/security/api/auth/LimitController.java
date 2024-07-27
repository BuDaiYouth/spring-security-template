package xyz.ibudai.security.api.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/limit")
public class LimitController {
    @GetMapping("/hello")
    public String hello() {
        return "limit resource";
    }
}
