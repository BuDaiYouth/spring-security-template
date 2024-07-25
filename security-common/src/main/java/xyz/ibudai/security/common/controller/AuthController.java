package xyz.ibudai.security.common.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/user/hello")
    public String hello1() {
        return "User say hello";
    }

    @GetMapping("/admin/hello")
    public String hello2() {
        return "Admin say hello";
    }

    @GetMapping("/ignored/hello")
    public String hello3() {
        return "Ignored resource";
    }

    @GetMapping("/whitelist/hello")
    public String hello4() {
        return "Whitelist resource";
    }
}
