package xyz.ibudai.security.api.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/user/hello")
    public String user() {
        return "User say hello";
    }

    @GetMapping("/admin/hello")
    public String admin() {
        return "Admin say hello";
    }

    @GetMapping("/ignored/hello")
    public String ignored() {
        return "Ignored resource";
    }

    @GetMapping("/whitelist/hello")
    public String whitelist() {
        return "Whitelist resource";
    }
}
