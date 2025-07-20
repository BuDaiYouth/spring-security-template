package xyz.ibudai.security.core.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import xyz.ibudai.security.core.model.enums.ResStatus;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResultData<T> {

    private int code;

    private String msg;

    private T data;

    public static <T> ResultData<T> success(T data) {
        ResultData<T> response = new ResultData<>();
        response.setCode(200);
        response.setMsg("success");
        response.setData(data);
        return response;
    }

    public static <T> ResultData<T> failed(String message) {
        ResultData<T> response = new ResultData<>();
        response.setCode(500);
        response.setMsg(message);
        response.setData(null);
        return response;
    }

    public static <T> ResultData<T> build(ResStatus status, T data) {
        ResultData<T> response = new ResultData<>();
        response.setCode(status.code());
        response.setMsg(status.message());
        response.setData(data);
        return response;
    }
}
