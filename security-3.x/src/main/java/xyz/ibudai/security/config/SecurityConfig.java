package xyz.ibudai.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.props.SecurityProps;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.common.SecurityConst;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.service.AuthUserService;
import xyz.ibudai.security.common.util.AESUtil;
import xyz.ibudai.security.common.util.TokenUtil;
import xyz.ibudai.security.common.encrypt.AESEncoder;
import xyz.ibudai.security.filter.TokenFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
// @EnableGlobalMethodSecurity 在 Security3 中已弃用
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Autowired
    private SecurityProps securityProps;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AuthUserService authUserService;

    /**
     * Security 3.x: authenticationManager() + authenticationProvider()
     * <p>
     * Security 2.x: configure(AuthenticationManagerBuilder auth)
     */
    @Bean
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // 创建一个用户认证提供者
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // 设置动态用户信息
        authProvider.setUserDetailsService(authUserService);
        // 设置加密机制
        authProvider.setPasswordEncoder(new AESEncoder());
        return authProvider;
    }

    /**
     * 配置忽略的地址
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        String[] whitelist = this.appendPrefix(securityProps.getWhitelist());
        return (web) -> web.ignoring().requestMatchers(whitelist);
    }

    /**
     * Security 3.x 通过注入 SecurityFilterChain 对象配置规则
     * <p>
     * Security 2.x 通过继承 WebSecurityConfigurerAdapter 并重写 configure(HttpSecurity) 实现
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 解析配置接口名单
        String[] userResource = this.appendPrefix(securityProps.getUserUrls());
        final String[] adminResource = this.appendPrefix(securityProps.getAdminUrls());
        final String[] commonResource = this.appendPrefix(securityProps.getCommonUrls());

        // 配置 security 作用规则
        http.authorizeHttpRequests(auth -> {
                    // 为不同权限分配不同资源
                    auth.requestMatchers(userResource).hasRole(SecurityConst.ROLE_USER)
                            .requestMatchers(adminResource).hasRole(SecurityConst.ROLE_ADMIN)
                            // permitAll(): 任意角色都可访问
                            .requestMatchers(commonResource).permitAll()
                            // 默认无定义资源都需认证
                            .anyRequest().authenticated();
                }).httpBasic(Customizer.withDefaults()).formLogin(form -> {
                    // 配置登录接口
                    form.loginProcessingUrl(securityProps.getLoginUrl().trim()).permitAll()
                            // 登录成功处理逻辑
                            .successHandler(this::successHandle)
                            // 登录失败处理逻辑
                            .failureHandler(this::failureHandle);
                }).logout(LogoutConfigurer::permitAll).exceptionHandling(handle -> {
                    // 无认证异常处理逻辑
                    handle.authenticationEntryPoint(this::unAuthHandle);
                })
                // 设置拦截器，同理还有 addFilterBefore()
                .addFilterAfter(new TokenFilter(), UsernamePasswordAuthenticationFilter.class)
                // 关闭跨站攻击
                .csrf(AbstractHttpConfigurer::disable)
                // 允许跨域
                .cors(Customizer.withDefaults());
        return http.build();
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
                    .map(it -> contextPath + it)
                    .toArray(String[]::new);
        }
        return urls;
    }

    /**
     * 认证登录成功处理
     * <p>
     * Request Head: Authorization = Basic xxx(auth)
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
            // 验证成功为用户生成过期时间为 12 小时的 Token
            String key = objectMapper.writeValueAsString(userDTO);
            token = TokenUtil.createJWT(key, TimeUnit.HOURS.toMillis(12));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // 将 Token 写入响应的请求头返回
        response.addHeader("token", token);
        String auth = user.getUsername() + ":" + user.getPassword();
        response.addHeader("auth", Base64.getEncoder().encodeToString(auth.getBytes()));
        response.setContentType(ContentType.JSON.value());
        ResultData<Object> result = new ResultData<>(ResStatus.SUCCESS.code(), ResStatus.SUCCESS.message(), true);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 认证登录失败处理
     * <p>
     * 有认证信息但验证不通过，根据对应类型进行提示
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
     * 未认证访问资源处理
     */
    private void unAuthHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setContentType(ContentType.JSON.value());

        ResStatus unAuth = ResStatus.UN_AUTHENTIC;
        log.error("Code: {}, Message: {}", unAuth.code(), unAuth.message());
        response.setStatus(unAuth.code());
        ResultData<Object> result = new ResultData<>(unAuth.code(), unAuth.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
