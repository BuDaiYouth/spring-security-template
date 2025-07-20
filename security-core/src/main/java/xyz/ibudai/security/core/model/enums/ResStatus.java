package xyz.ibudai.security.core.model.enums;

public enum ResStatus {

    LOGIN_SUCCESS(200, "Login success."),

    LOGOUT_SUCCESS(200, "Logout success."),

    ACCOUNT_LOCK(201, "Account locked, please contact the administrator."),

    BAD_CREDENTIAL(202, "Credential error, please recheck."),

    NOT_EXISTED(203, "Account doesn't exist, please register."),

    NOT_AUTHENTIC(204, "Not authentic, please login and try again."),

    LOGIN_EXPIRE(205, "Login expired, please login."),

    NOT_LOGIN(206, "Please login and try again."),

    INTERNAL_FAILED(207, "Internal failed, please contact the administrator");


    private final Integer code;

    private final String message;

    ResStatus(Integer code, String message) {
        this.code = code;
        this.message = message;
    }

    public Integer code() {
        return code;
    }

    public String message() {
        return message;
    }
}
