package xyz.ibudai.security.common.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import xyz.ibudai.security.common.entity.AuthUser;
import xyz.ibudai.security.common.service.AuthUserService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthUserService authUserService;

    @PostMapping("verify")
    public void authVerify(AuthUser user) {
    }

    @PostMapping("login")
    public boolean login(AuthUser user) throws Exception {
        return authUserService.login(user);
    }
}
