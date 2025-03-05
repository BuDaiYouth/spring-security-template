package xyz.ibudai.security2.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import xyz.ibudai.security.common.model.ResultData;
import xyz.ibudai.security.common.model.dto.AuthUserDTO;
import xyz.ibudai.security.common.model.enums.ContentType;
import xyz.ibudai.security.common.model.enums.ReqHeader;
import xyz.ibudai.security.common.model.enums.ResStatus;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.manager.service.Impl.AuthUserServiceImpl;
import xyz.ibudai.security.manager.service.TokenService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private TokenService tokenService;

    /**
     * 认证登录成功处理
     * <p>
     * getPrincipal() 返回结果为下述方法执行结果
     * {@link AuthUserServiceImpl#loadUserByUsername(String)}
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType(ContentType.JSON.value());

        AuthUser authUser = (AuthUser) authentication.getPrincipal();
        AuthUserDTO userDTO = tokenService.buildDetail(authUser);
        ResultData<AuthUserDTO> data = ResultData.build(ResStatus.LOGIN_SUCCESS, userDTO);
        response.addHeader(ReqHeader.BACK_TOKEN.value(), userDTO.getToken());
        response.addHeader(ReqHeader.BACK_AUTH.value(), userDTO.getAuthentic());
        response.getWriter().write(objectMapper.writeValueAsString(data));
    }
}
