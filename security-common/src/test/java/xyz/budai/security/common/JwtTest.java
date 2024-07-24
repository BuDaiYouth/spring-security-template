package xyz.budai.security.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import xyz.ibudai.security.common.model.vo.AuthUser;
import xyz.ibudai.security.common.util.TokenUtil;

public class JwtTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        AuthUser authUser = new AuthUser();
        authUser.setUsername("budai");
        authUser.setPassword("1234");
        authUser.setRole("ADMIN");

        String token = TokenUtil.createJWT(mapper.writeValueAsString(authUser), TokenUtil.JWT_TTL);
        System.out.println("Token value: " + token);

        try {
            // Recover token
            Claims claims = TokenUtil.parseJWT(token);
            String data = (String) claims.get("sub");
            System.out.println("Data: " + data);
        } catch (ExpiredJwtException e) {
            System.out.println("User is expired.");
        }
    }
}
