package xyz.ibudai.security.core.encrypt;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;

public class NoneEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return charSequence.toString();
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return Objects.equals(charSequence.toString(), s);
    }
}
