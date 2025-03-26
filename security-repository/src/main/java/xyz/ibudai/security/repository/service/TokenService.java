package xyz.ibudai.security.repository.service;

import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.model.vo.AuthUser;

public interface TokenService {

    /**
     * 认证用户构建
     *
     * @param user 登录用户
     */
    AuthUserDTO buildDetail(AuthUser user);

}
