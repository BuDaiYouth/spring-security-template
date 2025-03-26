package xyz.ibudai.security.repository.security.handler;

import org.springframework.stereotype.Service;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.repository.security.context.SecurityUtils;

import java.util.Objects;

@Service("ph")
public class PermitHandler {

    public boolean isPermit(String role) {
        AuthUser user = SecurityUtils.getUser();
        return Objects.equals(role, user.getRole());
    }
}
