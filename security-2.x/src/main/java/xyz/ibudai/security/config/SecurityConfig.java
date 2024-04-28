package xyz.ibudai.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import xyz.ibudai.security.common.entity.AuthUser;
import xyz.ibudai.security.common.entity.common.ResultData;
import xyz.ibudai.security.common.entity.dto.AuthUserDTO;
import xyz.ibudai.security.common.service.AuthUserService;
import xyz.ibudai.security.common.util.AESUtil;
import xyz.ibudai.security.common.util.TokenUtil;
import xyz.ibudai.security.common.encrypt.AESEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${auth.security.verify}")
    private String verifyAPI;

    @Value("${auth.security.user}")
    private String userAPI;

    @Value("${auth.security.admin}")
    private String adminAPI;

    @Value("${auth.security.common}")
    private String commonAPI;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuthUserService authUserService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 动态读取数据库信息
        auth.userDetailsService(authUserService)
                // 自定义 AES 方式加密
                .passwordEncoder(new AESEncoder());
    }

    /**
     * USER: 只能访问特定资源
     * ADMIN: 可以访问所有资源
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String[] userResource = userAPI.trim().split(",");
        String[] adminResource = adminAPI.trim().split(",");
        String[] commonResource = commonAPI.trim().split(",");
        http.authorizeRequests()
                // 为不同权限分配不同资源
                .antMatchers(userResource).hasRole("USER")
                .antMatchers(adminResource).hasRole("ADMIN")
                // 设置通用资源
                .antMatchers(commonResource).permitAll()
                // 默认无定义资源都需认证
                .anyRequest().authenticated()
                // 自定义认证访问资源
                .and().formLogin().loginProcessingUrl(verifyAPI)
                // 认证成功逻辑
                .successHandler(this::successHandle)
                // 认证失败逻辑
                .failureHandler(this::failureHandle)
                // 未认证访问受限资源逻辑
                .and().exceptionHandling().authenticationEntryPoint(this::unAuthHandle)
                .and().httpBasic()
                // 允许跨域
                .and().cors()
                // 关闭跨站攻击
                .and().csrf().disable();
    }

    private void successHandle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        AuthUser user = (AuthUser) authentication.getPrincipal();
        String token, plainPwd;
        try {
            AuthUserDTO userDTO = new AuthUserDTO();
            plainPwd = AESUtil.desEncrypt(user.getPassword()).trim();
            userDTO.setUsername(user.getUsername());
            userDTO.setPassword(plainPwd);
            userDTO.setRole(user.getRole());
            String key = objectMapper.writeValueAsString(userDTO);
            token = TokenUtil.createJWT(key, TimeUnit.MINUTES.toMillis(60));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        response.addHeader("token", token);
        String auth = user.getUsername() + ":" + user.getPassword();
        response.addHeader("auth", "Basic " + Base64.getEncoder().encodeToString(auth.getBytes()));
        response.setContentType("application/json;charset=UTF-8");
        ResultData<Object> result = new ResultData<>(200, "success", true);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    private void failureHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String msg;
        if (exception instanceof LockedException) {
            msg = "Account has been locked, please contact the administrator.";
        } else if (exception instanceof BadCredentialsException) {
            msg = "Account credential error, please recheck.";
        } else {
            msg = "Account doesn't exist, please recheck.";
        }
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(203);
        ResultData<Object> result = new ResultData<>(203, msg, null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    private void unAuthHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String msg = "Please login and try again.";
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(203);
        ResultData<Object> result = new ResultData<>(203, msg, null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
