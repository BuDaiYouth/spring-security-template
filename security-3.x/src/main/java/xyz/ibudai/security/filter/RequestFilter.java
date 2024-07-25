package xyz.ibudai.security.filter;

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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ReqHeader;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.security.context.SecurityUtils;
import xyz.ibudai.security.common.util.TokenUtil;

import java.io.IOException;
import java.util.Arrays;

/**
 * Each request will trigger the {@link RequestFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
 */
@Slf4j
public class RequestFilter extends OncePerRequestFilter {

    @Value("${auth.filter.enabled}")
    private boolean enabledFilter;
    @Value("${server.servlet.context-path}")
    private String contextPath;
    @Value("${auth.filter.whitelist}")
    private String whitelistUrl;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AntPathMatcher antPathMatcher;


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (!enabledFilter || this.excludesUrl(request.getRequestURI())) {
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
                Claims claims = TokenUtil.parseJWT(token);
                String sbu = claims.get("sub").toString();
                authUser = objectMapper.readValue(sbu, AuthUser.class);
            } catch (ExpiredJwtException e) {
                isExpired = true;
            }

            if (!isExpired) {
                // 登录未过期则转存用户信息至上下文
                this.fillAuthentic(authUser);
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
        ResultData<Object> result = new ResultData<>(resStatus.code(), resStatus.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    /**
     * 缓存信息至上下文
     *
     * @param authUser 登录用户
     */
    private void fillAuthentic(AuthUser authUser) {
        Authentication auth = new UsernamePasswordAuthenticationToken(authUser, null, authUser.getAuthorities());
        SecurityUtils.setAuthentication(auth);
    }

    /**
     * 过滤请求是否白名单
     *
     * @param path 请求接口
     */
    private boolean excludesUrl(String path) {
        boolean isMarch = false;
        try {
            String[] excludesResource = whitelistUrl.split(",");
            if (!StringUtils.isBlank(contextPath) && excludesResource.length > 0) {
                excludesResource = Arrays.stream(excludesResource)
                        .map(it -> contextPath + it.trim())
                        .toArray(String[]::new);
            }

            for (String pattern : excludesResource) {
                if (antPathMatcher.match(pattern, path)) {
                    isMarch = true;
                    break;
                }
            }
        } catch (Exception e) {
            log.error("Verify path failed", e);
        }
        return isMarch;
    }

    public static void main(String[] args) {
        AntPathMatcher pathMatcher = new AntPathMatcher();
        System.out.println(pathMatcher.match("/api/sys/**", "/api/sys/hello"));
    }
}
