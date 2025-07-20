package xyz.ibudai.security.core.model.enums;

public enum ReqHeader {

    BACK_AUTH("auth"),

    BACK_TOKEN("token"),

    FRONT_AUTH("Authorization"),

    FRONT_TOKEN("Token");


    private final String value;

    ReqHeader(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
