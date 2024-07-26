package xyz.ibudai.security3.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;
import xyz.ibudai.security.common.model.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ReqHeader;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.util.PathUtils;
import xyz.ibudai.security.common.util.TokenUtils;
import xyz.ibudai.security.manager.security.context.SecurityUtils;

import java.io.IOException;

/**
 * Each request will trigger the {@link Security3TokenFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
 */
@Slf4j
public class Security3TokenFilter extends OncePerRequestFilter {

    @Value("${auth.filter.enabled}")
    private boolean enabledFilter;
    @Value("${server.servlet.context-path}")
    private String contextPath;
    @Value("${auth.filter.whitelist}")
    private String whitelistUrl;

    @Autowired
    private ObjectMapper objectMapper;


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String requestURI = request.getRequestURI();
        if (!enabledFilter || PathUtils.excludesUrl(whitelistUrl, requestURI, contextPath)) {
            // 未开启登录拦截或访问资源免认证
            filterChain.doFilter(request, response);
            return;
        }

        ResStatus resStatus;
        String token = request.getHeader(ReqHeader.FRONT_TOKEN.value());
        if (StringUtils.isNotBlank(token)) {
            AuthUser authUser = null;
            boolean isExpired = false;
            try {
                // 根据请求头解析用户信息
                Claims claims = TokenUtils.parseJWT(token);
                String sbu = claims.get("sub").toString();
                authUser = objectMapper.readValue(sbu, AuthUser.class);
            } catch (ExpiredJwtException e) {
                isExpired = true;
            }

            if (!isExpired) {
                // 登录未过期则转存用户信息至上下文供本次请求后续使用
                SecurityUtils.setAuthentication(authUser);
                filterChain.doFilter(request, response);
                return;
            } else {
                resStatus = ResStatus.LOGIN_EXPIRE;
            }
        } else {
            resStatus = ResStatus.NOT_LOGIN;
        }
        // 写入异常提示返回请求
        response.setContentType(ContentType.JSON.value());
        response.setStatus(resStatus.code());
        response.getWriter().write(objectMapper.writeValueAsString(ResultData.build(resStatus, null)));
    }
}
