package xyz.ibudai.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.util.TokenUtil;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
@Component
public class TokenFilter implements Filter {

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Value("${auth.filter.enabled}")
    private boolean enabledFilter;
    @Value("${server.servlet.context-path}")
    private String contextPath;
    @Value("${auth.filter.excludes}")
    private String excludesApi;


    @Autowired
    private ObjectMapper objectMapper;

    /**
     * 每次请求读取请求头 Token 验证是否登录
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        if (!enabledFilter || this.excludesUrl(req.getRequestURI())) {
            filterChain.doFilter(req, servletResponse);
            return;
        }

        ResStatus resStatus;
        String token = req.getHeader("Token");
        if (StringUtils.isNotBlank(token)) {
            boolean isExpired = false;
            try {
                TokenUtil.parseJWT(token);
            } catch (ExpiredJwtException e) {
                isExpired = true;
            }

            if (!isExpired) {
                filterChain.doFilter(req, servletResponse);
                return;
            } else {
                resStatus = ResStatus.LOGIN_EXPIRE;
            }
        } else {
            resStatus = ResStatus.NOT_LOGIN;
        }
        response.setContentType(ContentType.JSON.value());
        response.setStatus(resStatus.code());
        ResultData<Object> result = new ResultData<>(resStatus.code(), resStatus.message(), null);
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

    private boolean excludesUrl(String path) {
        boolean isMarch = false;
        try {
            String[] excludesResource = excludesApi.split(",");
            if (!StringUtils.isBlank(contextPath)) {
                if (excludesResource.length > 0) {
                    excludesResource = Arrays.stream(excludesResource)
                            .map(it -> contextPath + it)
                            .toArray(String[]::new);
                }
            }

            for (String pattern : excludesResource) {
                isMarch = pathMatcher.match(pattern, path);
                if (isMarch) {
                    break;
                }
            }
        } catch (Exception e) {
            log.error("Verify path failed", e);
        }
        return isMarch;
    }
}
