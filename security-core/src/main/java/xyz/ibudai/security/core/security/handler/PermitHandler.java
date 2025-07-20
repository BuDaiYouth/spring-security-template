package xyz.ibudai.security.core.security.handler;

import org.springframework.stereotype.Service;
import xyz.ibudai.security.core.model.vo.AuthUser;
import xyz.ibudai.security.core.security.context.SecurityUtils;

import java.util.Objects;

@Service("ph")
public class PermitHandler {

    public boolean isPermit(String role) {
        AuthUser user = SecurityUtils.getUser();
        return Objects.equals(role, user.getRole());
    }
}
