package xyz.ibudai.security.repository.service;

import xyz.ibudai.security.core.model.dto.AuthUserDTO;
import xyz.ibudai.security.core.model.vo.AuthUser;

public interface LoginService {

    /**
     * 手动登录
     *
     * @param authUser 登录用户
     */
    AuthUserDTO manualLogin(AuthUser authUser);

    /**
     * 手动登出
     */
    AuthUserDTO manualLogout();
}
