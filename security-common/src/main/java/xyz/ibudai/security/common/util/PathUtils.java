package xyz.ibudai.security.common.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;

@Slf4j
public class PathUtils {

    private static final AntPathMatcher matcher = new AntPathMatcher();

    /**
     * 过滤请求是否白名单
     *
     * @param path 请求接口
     */
    public static boolean excludesUrl(String urls, String path, String contextPath) {
        boolean isMarch = false;
        try {
            String[] excludesResource = urls.split(",");
            if (!StringUtils.isBlank(contextPath) && excludesResource.length > 0) {
                excludesResource = Arrays.stream(excludesResource)
                        .map(it -> contextPath + it.trim())
                        .toArray(String[]::new);
            }

            for (String pattern : excludesResource) {
                if (matcher.match(pattern, path)) {
                    isMarch = true;
                    break;
                }
            }
        } catch (Exception e) {
            log.error("Verify path failed", e);
        }
        return isMarch;
    }
}
