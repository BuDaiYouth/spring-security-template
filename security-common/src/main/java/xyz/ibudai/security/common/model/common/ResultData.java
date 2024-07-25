package xyz.ibudai.security.common.model.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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


    public static ResultData<Void> failed(String message) {
        ResultData<Void> response = new ResultData<>();
        response.setCode(500);
        response.setMsg(message);
        response.setData(null);
        return response;
    }
}
