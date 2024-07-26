package xyz.ibudai.security.manager.service.Impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.manager.service.LoginService;
import xyz.ibudai.security.manager.service.TokenService;

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private TokenService tokenService;
    @Autowired(required = false)
    private AuthenticationManager authenticationManager;

    /**
     * authenticate() 方法会去调用 {@link AuthUserServiceImpl#loadUserByUsername(String)}
     *
     * @param authUser 登录用户
     */
    @Override
    public AuthUserDTO manualLogin(AuthUser authUser) {
        String username = authUser.getUsername();
        String password = authUser.getPassword();
        Authentication authentic = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        AuthUser principal = (AuthUser) authentic.getPrincipal();
        return tokenService.buildDetail(principal);
    }

    @Override
    public AuthUserDTO manualLogout() {
        return null;
    }
}
