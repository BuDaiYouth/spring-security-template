package xyz.budai.security.common;

import xyz.ibudai.security.common.util.AESUtils;

public class TokenTest {

    public static void main(String[] args) throws Exception {
        String data = "123456";
        String result = AESUtils.encrypt(data);
        System.out.println(result);
    }
}
