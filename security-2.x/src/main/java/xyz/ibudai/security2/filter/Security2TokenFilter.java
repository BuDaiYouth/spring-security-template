package xyz.ibudai.security2.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.common.model.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ReqHeader;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.util.TokenUtil;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class Security2TokenFilter implements Filter {

    @Value("${auth.filter.enabled}")
    private boolean enabledFilter;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        if (!enabledFilter) {
            filterChain.doFilter(req, servletResponse);
            return;
        }
        String token = req.getHeader(ReqHeader.FRONT_TOKEN.value());
        if (StringUtils.isBlank(token)) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setContentType(ContentType.JSON.value());
            response.setStatus(ResStatus.NOT_LOGIN.code());
            response.getWriter().write(objectMapper.writeValueAsString(ResultData.build(ResStatus.NOT_LOGIN, null)));
            return;
        }

        try {
            TokenUtil.parseJWT(token);
            filterChain.doFilter(req, servletResponse);
        } catch (ExpiredJwtException ignored) {
        }
    }
}
