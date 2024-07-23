package xyz.ibudai.security.common.handler;

import org.springframework.stereotype.Service;

import java.util.Objects;

@Service("ph")
public class PermitHandler {

    public boolean isPermit(String role) {
        return Objects.equals(role, "admin");
    }
}
