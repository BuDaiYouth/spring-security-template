package xyz.ibudai.security.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import xyz.ibudai.security.core.model.ResultData;
import xyz.ibudai.security.core.model.enums.ContentType;
import xyz.ibudai.security.core.model.enums.ReqHeader;
import xyz.ibudai.security.core.model.enums.ResStatus;
import xyz.ibudai.security.core.model.props.FilterProps;
import xyz.ibudai.security.core.model.vo.AuthUser;
import xyz.ibudai.security.core.security.context.SecurityUtils;
import xyz.ibudai.security.core.util.TokenUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenFilter extends OncePerRequestFilter {

    private final FilterProps filterProps;

    private final ObjectMapper objectMapper;
    private final AntPathMatcher antPathMatcher;


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestURI = request.getRequestURI();
        return !filterProps.getEnabled()
                || isWhitelist(requestURI, filterProps.getWhiteList());
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
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


    private boolean isWhitelist(String path, String[] urls) {
        boolean isMarch = false;
        for (String pattern : urls) {
            if (antPathMatcher.match(pattern, path)) {
                isMarch = true;
                break;
            }
        }
        return isMarch;
    }
}
