package xyz.ibudai.security.core.util;

import io.jsonwebtoken.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class TokenUtils {

    /**
     * 密钥
     */
    public static final String JWT_KEY = "ibudai";
    /**
     * 过期时间
     */
    public static final Long JWT_TTL = TimeUnit.MINUTES.toMillis(5);


    /**
     * 生成 Token
     *
     * @param data      the data
     * @param ttlMillis the expired time
     */
    public static String createJWT(String data, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(data, ttlMillis);
        return builder.compact();
    }

    /**
     * 解析 Token
     *
     * @param token the token
     */
    public static Claims parseJWT(String token) {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 生成加密后的秘钥
     */
    private static SecretKey generalKey() {
        byte[] encodedKey = Base64.getEncoder().encode(JWT_KEY.getBytes());
        return new SecretKeySpec(
                encodedKey,
                0,
                encodedKey.length,
                "AES"
        );
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis) {
        long nowMillis = System.currentTimeMillis();
        if (ttlMillis == null) {
            // default expire time 5 minute
            ttlMillis = JWT_TTL;
        }
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                // 计算内容
                .setSubject(subject)
                // 签发者
                .setIssuer("budai")
                // 签发时间
                .setIssuedAt(new Date(nowMillis))
                // 加密算法签名
                .signWith(SignatureAlgorithm.HS256, generalKey())
                .setExpiration(new Date(nowMillis + ttlMillis));
    }
}
