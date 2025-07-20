package xyz.ibudai.security.core.model.enums;

public enum ContentType {

    JSON("application/json;charset=UTF-8");

    private final String value;

    ContentType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
