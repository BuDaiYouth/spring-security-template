package xyz.ibudai.security3.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
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
import xyz.ibudai.security.common.consts.SecurityConst;
import xyz.ibudai.security.common.encrypt.AESEncoder;
import xyz.ibudai.security.common.model.props.SecurityProps;
import xyz.ibudai.security.manager.service.AuthUserService;
import xyz.ibudai.security3.filter.Security3TokenFilter;
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
public class Security3Config {

    @Autowired
    private SecurityProps securityProps;
    @Autowired
    private AuthUserService authUserService;


    @Bean
    public Security3TokenFilter requestFilter() {
        return new Security3TokenFilter();
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler();
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public AuthLogoutHandler authLogoutHandler() {
        return new AuthLogoutHandler();
    }

    @Bean
    public AuthExceptionHandler authExceptionHandler() {
        return new AuthExceptionHandler();
    }

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
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        String[] ignoredResource = this.appendPrefix(securityProps.getIgnoreUrls());
        return (web) -> web.ignoring().requestMatchers(ignoredResource);
    }

    /**
     * Security 3.x 通过注入 SecurityFilterChain 对象配置规则
     * <p>
     * Security 2.x 通过继承 WebSecurityConfigurerAdapter 并重写 configure(HttpSecurity) 实现
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 解析配置接口名单
        final String[] userResource = this.appendPrefix(securityProps.getUserUrls());
        final String[] adminResource = this.appendPrefix(securityProps.getAdminUrls());
        final String[] whitelistResource = this.appendPrefix(securityProps.getWhitelist());

        // 配置 security 作用规则
        http.authorizeHttpRequests(auth -> {
                    // 为不同权限分配不同资源
                    auth.requestMatchers(userResource).hasRole(SecurityConst.ROLE_USER)
                            .requestMatchers(adminResource).hasRole(SecurityConst.ROLE_ADMIN)
                            // permitAll(): 任意角色都可访问
                            .requestMatchers(whitelistResource).permitAll()
                            // 默认无定义资源都需认证
                            .anyRequest().authenticated();
                })
                .httpBasic(Customizer.withDefaults())
                // 配置登录接口
                .formLogin(form -> {
                    form.loginProcessingUrl(securityProps.getLoginUrl().trim()).permitAll()
                            // 登录成功处理逻辑
                            .successHandler(loginSuccessHandler())
                            // 登录失败处理逻辑
                            .failureHandler(loginFailureHandler());
                })
                // 登出逻辑
                .logout(it -> {
                    it.logoutUrl(securityProps.getLogoutUrl().trim()).permitAll()
                            .logoutSuccessUrl(securityProps.getLogoutSuccessUrl().trim()).permitAll()
                            // 登出处理器
                            .addLogoutHandler(authLogoutHandler());
                })
                // 认证异常处理逻辑
                .exceptionHandling(handle -> {
                    handle.authenticationEntryPoint(authExceptionHandler());
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

        return url.trim().split(",");
    }
}
