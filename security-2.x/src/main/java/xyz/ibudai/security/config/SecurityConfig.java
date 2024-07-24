package xyz.ibudai.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import xyz.ibudai.security.common.model.common.SecurityConst;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.props.SecurityProps;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.service.AuthUserService;
import xyz.ibudai.security.common.util.AESUtil;
import xyz.ibudai.security.common.util.TokenUtil;
import xyz.ibudai.security.common.encrypt.AESEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Autowired
    private SecurityProps securityProps;
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
        String[] userResource = this.appendPrefix(securityProps.getUserUrls());
        String[] adminResource = this.appendPrefix(securityProps.getAdminUrls());
        String[] commonResource = this.appendPrefix(securityProps.getCommonUrls());
        http.authorizeRequests()
                // 为不同权限分配不同资源
                .antMatchers(userResource).hasAnyRole(SecurityConst.ROLE_USER)
                .antMatchers(adminResource).hasAnyRole(SecurityConst.ROLE_ADMIN)
                // 设置通用资源
                .antMatchers(commonResource).permitAll()
                // 默认无定义资源都需认证
                .anyRequest().authenticated()
                // 自定义认证访问资源
                .and().formLogin().loginProcessingUrl(securityProps.getLoginUrl().trim())
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

    /**
     * 资源拆分拼接
     *
     * @param url 资源路径
     */
    private String[] appendPrefix(String url) {
        if (StringUtils.isBlank(url)) {
            throw new IllegalArgumentException("Url resource can't be blank!");
        }

        String[] urls = url.trim().split(",");
        if (urls.length > 0) {
            urls = Arrays.stream(urls)
                    .map(it -> contextPath + it.trim())
                    .toArray(String[]::new);
        }
        return urls;
    }

    /**
     * 认证成功处理逻辑
     */
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
        response.setContentType(ContentType.JSON.value());
        ResultData<Object> result = new ResultData<>(ResStatus.SUCCESS.code(), ResStatus.SUCCESS.message(), true);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 认证失败处理逻辑
     */
    private void failureHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        ResStatus resStatus;
        if (exception instanceof LockedException) {
            resStatus = ResStatus.ACCOUNT_LOCK;
        } else if (exception instanceof BadCredentialsException) {
            resStatus = ResStatus.BAD_CREDENTIAL;
        } else {
            resStatus = ResStatus.NOT_EXISTED;
        }
        response.setContentType(ContentType.JSON.value());
        response.setStatus(resStatus.code());
        ResultData<Object> result = new ResultData<>(resStatus.code(), resStatus.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 无认证处理逻辑
     */
    private void unAuthHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setContentType(ContentType.JSON.value());

        ResStatus unAuth = ResStatus.NOT_AUTHENTIC;
        log.error("Code: {}, Message: {}", unAuth.code(), unAuth.message());
        response.setStatus(unAuth.code());
        ResultData<Object> result = new ResultData<>(unAuth.code(), unAuth.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
