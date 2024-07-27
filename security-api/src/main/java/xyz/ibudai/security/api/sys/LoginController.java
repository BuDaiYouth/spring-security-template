package xyz.ibudai.security.api.sys;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.manager.service.LoginService;

@RestController
@RequestMapping("/api/sys")
public class LoginController {

    @Autowired
    private LoginService loginService;

    @PostMapping("login")
    public void login(AuthUser user) {
    }

    /**
     * 手动登录
     *
     * @param user 用户
     */
    @PostMapping("manualLogin")
    public AuthUserDTO manualLogin(@RequestBody AuthUser user) {
        return loginService.manualLogin(user);
    }

    /**
     * 登出
     */
    @PostMapping("logout")
    public void logout(AuthUser user) {
    }

    /**
     * 手动登出
     */
    @PostMapping("manualLogout")
    public void manualLogout() {
        loginService.manualLogout();
    }
}
