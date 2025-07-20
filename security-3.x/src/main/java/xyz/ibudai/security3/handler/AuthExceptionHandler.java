package xyz.ibudai.security3.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.core.model.ResultData;
import xyz.ibudai.security.core.model.enums.ContentType;
import xyz.ibudai.security.core.model.enums.ResStatus;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthExceptionHandler implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;


    /**
     * 认证失败处理
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("The request is not authentic");

        ResultData<Void> data = ResultData.build(ResStatus.NOT_AUTHENTIC, null);
        response.setContentType(ContentType.JSON.value());
        response.setStatus(ResStatus.NOT_AUTHENTIC.code());
        response.getWriter().write(objectMapper.writeValueAsString(data));
    }
}
