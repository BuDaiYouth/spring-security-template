package xyz.ibudai.security3.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.core.model.ResultData;
import xyz.ibudai.security.core.model.enums.ContentType;
import xyz.ibudai.security.core.model.enums.ResStatus;

import java.io.IOException;

@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthLogoutHandler implements LogoutHandler {

    private final ObjectMapper objectMapper;


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
