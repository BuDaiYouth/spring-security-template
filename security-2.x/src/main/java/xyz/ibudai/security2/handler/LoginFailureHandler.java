package xyz.ibudai.security2.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.core.model.ResultData;
import xyz.ibudai.security.core.model.enums.ContentType;
import xyz.ibudai.security.core.model.enums.ResStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;


    /**
     * 认证登录失败处理
     * <p>
     * 有认证信息但验证不通过，根据对应类型进行提示
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        ResStatus resStatus;
        if (exception instanceof LockedException) {
            resStatus = ResStatus.ACCOUNT_LOCK;
        } else if (exception instanceof BadCredentialsException) {
            resStatus = ResStatus.BAD_CREDENTIAL;
        } else {
            resStatus = ResStatus.NOT_EXISTED;
        }

        ResultData<Object> data = ResultData.build(resStatus, null);
        response.setContentType(ContentType.JSON.value());
        response.setStatus(resStatus.code());
        response.getWriter().write(objectMapper.writeValueAsString(data));
    }
}
