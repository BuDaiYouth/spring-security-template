package xyz.ibudai.security2.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.common.model.ResultData;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ResStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthLogoutHandler implements LogoutHandler {

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * 登出处理
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            ResultData<Void> data = ResultData.build(ResStatus.LOGOUT_SUCCESS, null);
            response.setContentType(ContentType.JSON.value());
            response.getWriter().write(objectMapper.writeValueAsString(data));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
