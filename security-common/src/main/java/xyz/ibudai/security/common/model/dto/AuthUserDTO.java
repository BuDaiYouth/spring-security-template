package xyz.ibudai.security.common.model.dto;

import lombok.Data;

@Data
public class AuthUserDTO {

    private String username;

    private String password;

    private String role;

}
