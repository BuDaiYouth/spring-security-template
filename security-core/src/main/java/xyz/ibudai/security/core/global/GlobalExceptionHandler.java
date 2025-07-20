package xyz.ibudai.security.core.global;

import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import xyz.ibudai.security.core.model.ResultData;

@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 监听异常请求并处理返回
     */
    @ExceptionHandler(Exception.class)
    public ResultData<String> handleNotFoundException(Exception e) {
        return ResultData.failed(e.getMessage());
    }
}
