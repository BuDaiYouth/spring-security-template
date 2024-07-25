package xyz.ibudai.security.common.controller.sys;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.service.Impl.AuthUserServiceImpl;

@RestController
@RequestMapping("/api/sys")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("login")
    public void login(AuthUser user) {
    }

    /**
     * authenticate() 方法会去调用 {@link AuthUserServiceImpl#loadUserByUsername(String)}
     *
     * @param user 用户
     */
    @PostMapping("manualLogin")
    public AuthUser manualLogin(@RequestBody AuthUser user) {
        String username = user.getUsername();
        String password = user.getPassword();
        Authentication authentic = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return (AuthUser) authentic.getPrincipal();
    }
}
