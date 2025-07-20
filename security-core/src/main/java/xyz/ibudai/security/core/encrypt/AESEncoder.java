package xyz.ibudai.security.core.encrypt;

import org.springframework.security.crypto.password.PasswordEncoder;
import xyz.ibudai.security.core.util.AESUtils;

import java.util.Objects;

public class AESEncoder implements PasswordEncoder {

    /**
     * "str" should use difference key encode,
     * and backend decrypt then encrypt with diff key
     *
     * @param charSequence user input password
     */
    @Override
    public String encode(CharSequence charSequence) {
        String str = charSequence.toString();
        try {
            return AESUtils.encrypt(str);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @param charSequence user input password
     * @param s            database password
     */
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        try {
            String result = AESUtils.encrypt(charSequence.toString());
            return Objects.equals(result, s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
