package xyz.ibudai.security.common.response;

import org.springframework.web.bind.annotation.RestControllerAdvice;
import xyz.ibudai.security.common.model.ResultData;

@RestControllerAdvice
public class ExceptionHandler {

    /**
     * 监听异常请求并处理返回
     */
    @org.springframework.web.bind.annotation.ExceptionHandler(Exception.class)
    public ResultData<String> handleNotFoundException(Exception ex) {
        return ResultData.failed(ex.getMessage());
    }
}
