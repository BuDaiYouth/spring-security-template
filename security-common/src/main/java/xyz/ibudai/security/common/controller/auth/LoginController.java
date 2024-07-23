package xyz.ibudai.security.common.controller.auth;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import xyz.ibudai.security.common.model.vo.AuthUser;

@RestController
@RequestMapping("/api/auth")
public class LoginController {

    @PostMapping("login")
    public void login(AuthUser user) {
    }
}
