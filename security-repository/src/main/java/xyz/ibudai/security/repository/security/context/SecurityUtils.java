package xyz.ibudai.security.repository.security.context;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import xyz.ibudai.security.common.model.vo.AuthUser;

public class SecurityUtils {

    public static AuthUser getUser() {
        return (AuthUser) getAuthentication().getPrincipal();
    }

    /**
     * 读取上下文认证信息
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 设置认证上下文信息
     *
     * @param authUser 登录用户
     */
    public static void setAuthentication(AuthUser authUser) {
        Authentication authentic = new UsernamePasswordAuthenticationToken(authUser, null, authUser.getAuthorities());
        setAuthentication(authentic);
    }

    /**
     * 设置认证上下文信息
     *
     * @param auth 认证信息
     */
    public static void setAuthentication(Authentication auth) {
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
