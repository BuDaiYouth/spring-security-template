package xyz.ibudai.security.api.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/hello")
    public String hello() {
        return "User say hello";
    }

    @GetMapping("/goodbye")
    public String goodbye() {
        return "User say goodbye";
    }

    @GetMapping("/sec/hello")
    public String secHello() {
        return "User say hello twice.";
    }

    @GetMapping("/sec/goodbye")
    public String secGoodbye() {
        return "User say goodbye twice.";
    }
}
