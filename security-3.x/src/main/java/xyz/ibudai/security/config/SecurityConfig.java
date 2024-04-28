package xyz.ibudai.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import xyz.ibudai.security.common.entity.AuthUser;
import xyz.ibudai.security.common.entity.common.ResultData;
import xyz.ibudai.security.common.entity.dto.AuthUserDTO;
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

@Configuration
public class SecurityConfig {

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Value("${auth.security.ignore}")
    private String ignoredAPI;

    @Value("${auth.security.login}")
    private String loginAPI;

    @Value("${auth.security.common}")
    private String commonAPIs;

    @Value("${auth.security.user}")
    private String userAPIs;

    @Value("${auth.security.admin}")
    private String adminAPIs;

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
        String[] ignoredApis = ignoredAPI.split(",");
        return (web) -> web.ignoring()
                .requestMatchers(ignoredApis);
    }

    /**
     * Security 3.x 通过注入 SecurityFilterChain 对象配置规则
     * Security 2.x 通过继承 WebSecurityConfigurerAdapter 并重写 configure(HttpSecurity) 实现
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 解析配置接口名单
        String[] userUrls = userAPIs.trim().split(",");
        String[] adminUrls = adminAPIs.trim().split(",");
        String[] commonUrls = commonAPIs.trim().split(",");
        if (!StringUtils.isBlank(contextPath)) {
            if (commonUrls.length > 0) {
                commonUrls = Arrays.stream(commonUrls)
                        .map(it -> contextPath + it)
                        .toArray(String[]::new);
            }
            if (userUrls.length > 0) {
                userUrls = Arrays.stream(userUrls)
                        .map(it -> contextPath + it)
                        .toArray(String[]::new);
            }
            if (adminUrls.length > 0) {
                adminUrls = Arrays.stream(adminUrls)
                        .map(it -> contextPath + it)
                        .toArray(String[]::new);
            }
        }

        // 配置 security 作用规则
        final String[] userResource = userUrls;
        final String[] adminResource = adminUrls;
        final String[] commonResource = commonUrls;
        http
                .authorizeHttpRequests(auth -> {
                    auth
                            // 为不同权限分配不同资源
                            .requestMatchers(userResource).hasRole("USER")
                            .requestMatchers(adminResource).hasRole("ADMIN")
                            // permitAll(): 任意角色都可访问
                            .requestMatchers(commonResource).permitAll()
                            // 默认无定义资源都需认证
                            .anyRequest().authenticated();
                })
                .httpBasic(Customizer.withDefaults())
                .formLogin(form -> {
                    // 配置登录接口
                    form.loginProcessingUrl(loginAPI).permitAll()
                            // 登录成功处理逻辑
                            .successHandler(this::successHandle)
                            // 登录失败处理逻辑
                            .failureHandler(this::failureHandle);
                })
                .logout(LogoutConfigurer::permitAll)
                .exceptionHandling(handle -> {
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
        response.setContentType("application/json;charset=UTF-8");
        ResultData<Object> result = new ResultData<>(200, "login success.", true);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 认证登录失败处理
     */
    private void failureHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String msg;
        // 有认证信息但验证不通过，根据对应类型进行提示
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

    /**
     * 未认证访问资源处理
     */
    private void unAuthHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        // 无认证信息则提示进行登录
        String msg = "Authorization failure, please login and try again.";
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(203);
        ResultData<Object> result = new ResultData<>(203, msg, null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
