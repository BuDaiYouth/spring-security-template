package xyz.ibudai.security.api.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/hello")
    public String hello() {
        return "Admin say hello";
    }

    @GetMapping("/goodbye")
    public String goodbye() {
        return "Admin say goodbye";
    }

    @GetMapping("/sec/hello")
    public String secHello() {
        return "Admin say hello twice.";
    }

    @GetMapping("/sec/goodbye")
    public String secGoodbye() {
        return "Admin say goodbye twice.";
    }
}
