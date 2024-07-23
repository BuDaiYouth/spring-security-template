package xyz.ibudai.security.common.model.enums;

public enum ResStatus {

    SUCCESS(200, "Login success."),
    ACCOUNT_LOCK(201, "Account has been locked, contact the administrator."),
    BAD_CREDENTIAL(202, "Account credential error, please recheck."),
    NOT_EXISTED(203, "Account doesn't exist, please recheck."),
    UN_AUTHENTIC(204, "Authorization failure, please login and try again."),
    LOGIN_EXPIRE(205, "Login expired, please login."),
    NOT_LOGIN(206, "Please login and try again."),
    INTERNAL_FAILED(207, "Internal failed, contact the administrator");

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
