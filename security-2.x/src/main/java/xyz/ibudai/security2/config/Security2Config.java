package xyz.ibudai.security2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import xyz.ibudai.security.common.consts.SecurityConst;
import xyz.ibudai.security.common.props.SecurityProps;
import xyz.ibudai.security.common.encrypt.AESEncoder;
import xyz.ibudai.security.repository.service.AuthUserService;
import xyz.ibudai.security2.handler.AuthExceptionHandler;
import xyz.ibudai.security2.handler.LoginFailureHandler;
import xyz.ibudai.security2.handler.LoginSuccessHandler;

@Slf4j
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class Security2Config extends WebSecurityConfigurerAdapter {

    private final SecurityProps securityProps;
    private final AuthUserService authUserService;

    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final AuthExceptionHandler authExceptionHandler;


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
        // 认证配置
        http.authorizeRequests()
                // 为不同权限分配不同资源
                .antMatchers(securityProps.getUserUrls()).hasAnyRole(SecurityConst.ROLE_USER)
                .antMatchers(securityProps.getAdminUrls()).hasAnyRole(SecurityConst.ROLE_ADMIN)
                // 设置通用资源
                .antMatchers(securityProps.getCommonUrls()).permitAll()
                // 默认无定义资源都需认证
                .anyRequest().authenticated()
                // 自定义认证访问资源
                .and().formLogin().loginProcessingUrl(securityProps.getLoginUrl().trim())
                // 认证成功逻辑
                .successHandler(loginSuccessHandler)
                // 认证失败逻辑
                .failureHandler(loginFailureHandler)
                // 未认证访问受限资源逻辑
                .and().exceptionHandling().authenticationEntryPoint(authExceptionHandler)
                .and().httpBasic()
                // 允许跨域
                .and().cors()
                // 关闭跨站攻击
                .and().csrf().disable();
    }
}
