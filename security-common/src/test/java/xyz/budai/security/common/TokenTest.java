package xyz.budai.security.common;

import xyz.ibudai.security.common.util.AESUtil;

public class TokenTest {

    public static void main(String[] args) throws Exception {
        String data = "123456";
        String result = AESUtil.encrypt(data);
        System.out.println(result);
    }
}
