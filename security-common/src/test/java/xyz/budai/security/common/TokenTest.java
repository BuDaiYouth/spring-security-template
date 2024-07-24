package xyz.budai.security.common;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import xyz.ibudai.security.common.util.AESUtil;

import java.util.concurrent.TimeUnit;

public class TokenTest {

    public static void main(String[] args) throws Exception {
        String data = "123456";
        String result = AESUtil.encrypt(data);
        System.out.println(result);
    }
}
