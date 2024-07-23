package xyz.ibudai.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.common.model.common.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.util.TokenUtil;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class TokenFilter implements Filter {

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
        String token = req.getHeader("Token");
        if (StringUtils.isBlank(token)) {
            ResStatus resStatus = ResStatus.NOT_LOGIN;
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setContentType(ContentType.JSON.value());
            response.setStatus(resStatus.code());
            ResultData<Object> result = new ResultData<>(resStatus.code(), resStatus.message(), null);
            response.getWriter().write(objectMapper.writeValueAsString(result));
            return;
        }

        boolean expired = false;
        try {
            TokenUtil.parseJWT(token);
        } catch (ExpiredJwtException e) {
            expired = true;
        }
        if (!expired) {
            filterChain.doFilter(req, servletResponse);
        }
    }
}
