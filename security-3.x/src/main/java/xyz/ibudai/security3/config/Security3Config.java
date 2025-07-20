package xyz.ibudai.security3.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import xyz.ibudai.security.core.encrypt.AESEncoder;
import xyz.ibudai.security.core.filter.TokenFilter;
import xyz.ibudai.security.core.model.props.SecurityProps;
import xyz.ibudai.security.core.model.enums.RoleType;
import xyz.ibudai.security.repository.service.AuthUserService;
import xyz.ibudai.security3.handler.AuthExceptionHandler;
import xyz.ibudai.security3.handler.AuthLogoutHandler;
import xyz.ibudai.security3.handler.LoginFailureHandler;
import xyz.ibudai.security3.handler.LoginSuccessHandler;

import java.util.Collections;

/**
 * @EnableGlobalMethodSecurity 在 Security3 中已弃用
 */
@Slf4j
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class Security3Config {

    private final SecurityProps securityProps;
    private final AuthUserService authUserService;

    private final TokenFilter tokenFilter;

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final AuthLogoutHandler authLogoutHandler;
    private final AuthExceptionHandler authExceptionHandler;


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

    /**
     * 配置忽略的地址
     * <p>
     * 通常用于配置静态资源
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(securityProps.getIgnoreUrls());
    }

    /**
     * Security 3.x 通过注入 SecurityFilterChain 对象配置规则
     * <p>
     * Security 2.x 通过继承 WebSecurityConfigurerAdapter 并重写 configure(HttpSecurity) 实现
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 配置 security 作用规则
        http
                .authorizeHttpRequests(auth -> {
                    // 为不同权限分配不同资源
                    auth.requestMatchers(securityProps.getUserUrls()).hasRole(RoleType.USER.name());
                    auth.requestMatchers(securityProps.getAdminUrls()).hasRole(RoleType.ADMIN.name());
                    // permitAll(): 任意角色都可访问
                    auth.requestMatchers(securityProps.getCommonUrls()).permitAll();
                    // 默认无定义资源都需认证
                    auth.anyRequest().authenticated();
                })
                .httpBasic(Customizer.withDefaults())
                // 配置登录接口
                .formLogin(form -> {
                    form.loginProcessingUrl(securityProps.getLoginUrl().trim()).permitAll()
                            // 登录成功处理逻辑
                            .successHandler(loginSuccessHandler)
                            // 登录失败处理逻辑
                            .failureHandler(loginFailureHandler);
                })
                // 登出逻辑
                .logout(it -> {
                    it.logoutUrl(securityProps.getLogoutUrl().trim()).permitAll()
                            .logoutSuccessUrl(securityProps.getLogoutSuccessUrl().trim()).permitAll()
                            // 登出处理器
                            .addLogoutHandler(authLogoutHandler);
                })
                // 认证异常处理逻辑
                .exceptionHandling(handle -> {
                    handle.authenticationEntryPoint(authExceptionHandler);
                })
                // 设置拦截器
                .addFilterAfter(tokenFilter, UsernamePasswordAuthenticationFilter.class)
                // 关闭跨站攻击
                .csrf(AbstractHttpConfigurer::disable)
                // 允许跨域
                .cors(Customizer.withDefaults());
        return http.build();
    }
}
