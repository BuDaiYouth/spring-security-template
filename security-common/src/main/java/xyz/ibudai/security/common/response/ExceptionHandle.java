package xyz.ibudai.security.common.response;

import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import xyz.ibudai.security.common.model.common.ResultData;

@RestControllerAdvice
public class ExceptionHandle {

    /**
     * 监听异常请求并处理返回
     */
    @ExceptionHandler(Exception.class)
    public ResultData handleNotFoundException(Exception ex) {
        return ResultData.failed(ex.getMessage());
    }
}
