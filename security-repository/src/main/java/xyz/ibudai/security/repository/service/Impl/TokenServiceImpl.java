package xyz.ibudai.security.repository.service.Impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import xyz.ibudai.security.core.model.dto.AuthUserDTO;
import xyz.ibudai.security.core.model.vo.AuthUser;
import xyz.ibudai.security.core.model.props.JwtProps;
import xyz.ibudai.security.core.util.TokenUtils;
import xyz.ibudai.security.repository.service.TokenService;

import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenServiceImpl implements TokenService {

    private final JwtProps jwtProps;
    private final ObjectMapper objectMapper;


    @Override
    public AuthUserDTO buildDetail(AuthUser user) {
        AuthUserDTO userDTO = new AuthUserDTO();
        userDTO.setUsername(user.getUsername());
        userDTO.setPassword(user.getPassword());
        userDTO.setRole(user.getRole());
        try {
            // 生成用户 JWT Token
            String key = objectMapper.writeValueAsString(userDTO);
            String token = TokenUtils.createJWT(key, TimeUnit.MINUTES.toMillis(jwtProps.getExpireTime()));
            userDTO.setToken(token);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Authorization = Basic base64(username + password)
        String authentic = user.getUsername() + ":" + user.getPassword();
        authentic = Base64.getEncoder().encodeToString(authentic.getBytes());
        userDTO.setAuthentic(authentic);
        return userDTO;
    }
}
