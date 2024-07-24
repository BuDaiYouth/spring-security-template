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
import xyz.ibudai.security.common.model.enums.ReqHeader;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.props.SecurityProps;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.common.SecurityConst;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.service.AuthUserService;
import xyz.ibudai.security.common.util.TokenUtil;
import xyz.ibudai.security.common.encrypt.AESEncoder;
import xyz.ibudai.security.filter.RequestFilter;

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
    private ObjectMapper objectMapper;
    @Autowired
    private SecurityProps securityProps;
    @Autowired
    private AuthUserService authUserService;

    /**
     * Security 2.x: configure(AuthenticationManagerBuilder auth)
     * <p>
     * Security 3.x: authenticationManager() + authenticationProvider()
     */
    @Bean
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authenticationProvider()));
    }

    /**
     * 创建用户认证提供者
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // 设置动态用户信息
        authProvider.setUserDetailsService(authUserService);
        // 设置加密机制
        authProvider.setPasswordEncoder(new AESEncoder());
        return authProvider;
    }

    @Bean
    public RequestFilter requestFilter() {
        return new RequestFilter();
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
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
                })
                .httpBasic(Customizer.withDefaults())
                // 配置登录接口
                .formLogin(form -> {
                    form.loginProcessingUrl(securityProps.getLoginUrl().trim()).permitAll()
                            // 登录成功处理逻辑
                            .successHandler(this::loginSuccessHandle)
                            // 登录失败处理逻辑
                            .failureHandler(this::loginFailureHandle);
                })
                // 登出逻辑
                .logout(LogoutConfigurer::permitAll)
                // 无认证异常处理逻辑
                .exceptionHandling(handle -> {
                    handle.authenticationEntryPoint(this::unAuthHandle);
                })
                // 设置拦截器
                .addFilterBefore(requestFilter(), UsernamePasswordAuthenticationFilter.class)
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
            throw new IllegalArgumentException("Resource can't be blank!");
        }

        String[] urls = url.trim().split(",");
        if (urls.length > 0) {
            urls = Arrays.stream(urls).map(it -> contextPath + it).toArray(String[]::new);
        }
        return urls;
    }

    /**
     * 认证登录成功处理
     * <p>
     * getPrincipal() 返回结果为下述方法执行结果
     * {@link xyz.ibudai.security.common.service.Impl.AuthUserServiceImpl#loadUserByUsername(java.lang.String)}
     * <p>
     * Request Head:
     */
    private void loginSuccessHandle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        AuthUser user = (AuthUser) authentication.getPrincipal();
        try {
            AuthUserDTO userDTO = new AuthUserDTO();
            userDTO.setUsername(user.getUsername());
            userDTO.setPassword(user.getPassword());
            userDTO.setRole(user.getRole());
            // 验证成功为用户生成 30 分钟的 Token
            String key = objectMapper.writeValueAsString(userDTO);
            String token = TokenUtil.createJWT(key, TimeUnit.MINUTES.toMillis(30));
            response.addHeader(ReqHeader.BACK_TOKEN.value(), token);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Authorization = Bearer xxx
        String auth = user.getUsername() + ":" + user.getPassword();
        auth = Base64.getEncoder().encodeToString(auth.getBytes());
        response.addHeader(ReqHeader.BACK_AUTH.value(), auth);
        response.setContentType(ContentType.JSON.value());
        ResultData<Object> result = new ResultData<>(ResStatus.SUCCESS.code(), ResStatus.SUCCESS.message(), auth);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 认证登录失败处理
     * <p>
     * 有认证信息但验证不通过，根据对应类型进行提示
     */
    private void loginFailureHandle(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
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
        log.error("The request is not authentic");

        response.setContentType(ContentType.JSON.value());
        ResStatus unAuth = ResStatus.NOT_AUTHENTIC;
        response.setStatus(unAuth.code());
        ResultData<Object> result = new ResultData<>(unAuth.code(), unAuth.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
