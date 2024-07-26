package xyz.ibudai.security2.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import xyz.ibudai.security.common.consts.SecurityConst;
import xyz.ibudai.security.common.model.props.SecurityProps;
import xyz.ibudai.security.common.encrypt.AESEncoder;
import xyz.ibudai.security.manager.service.AuthUserService;
import xyz.ibudai.security2.handler.AuthExceptionHandler;
import xyz.ibudai.security2.handler.AuthLogoutHandler;
import xyz.ibudai.security2.handler.LoginFailureHandler;
import xyz.ibudai.security2.handler.LoginSuccessHandler;

@Slf4j
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class Security2Config extends WebSecurityConfigurerAdapter {

    @Autowired
    private SecurityProps securityProps;
    @Autowired
    private AuthUserService authUserService;

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
     * 用来将自定义 AuthenticationManager 在工厂中进行暴露
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

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
        String[] whitelistResource = this.appendPrefix(securityProps.getWhitelist());
        http.authorizeRequests()
                // 为不同权限分配不同资源
                .antMatchers(userResource).hasAnyRole(SecurityConst.ROLE_USER)
                .antMatchers(adminResource).hasAnyRole(SecurityConst.ROLE_ADMIN)
                // 设置通用资源
                .antMatchers(whitelistResource).permitAll()
                // 默认无定义资源都需认证
                .anyRequest().authenticated()
                // 自定义认证访问资源
                .and().formLogin().loginProcessingUrl(securityProps.getLoginUrl().trim())
                // 认证成功逻辑
                .successHandler(loginSuccessHandler())
                // 认证失败逻辑
                .failureHandler(loginFailureHandler())
                // 未认证访问受限资源逻辑
                .and().exceptionHandling().authenticationEntryPoint(authExceptionHandler())
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

        return url.trim().split(",");
    }
}
