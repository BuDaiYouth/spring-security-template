package xyz.ibudai.security.common.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

@Data
public class AuthUserDTO {

    private String username;

    @JsonIgnore
    private String password;

    private String role;

    private String token;

    private String authentic;

}
