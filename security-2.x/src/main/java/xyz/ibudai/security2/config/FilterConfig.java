package xyz.ibudai.security2.config;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import xyz.ibudai.security2.filter.Security2TokenFilter;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class FilterConfig {

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Value("${auth.filter.whitelist}")
    private String excludesApi;

    @Bean
    public FilterRegistrationBean<Security2TokenFilter> orderFilter1() {
        FilterRegistrationBean<Security2TokenFilter> filter = new FilterRegistrationBean<>();
        filter.setName("auth-filter");
        // Set effect url
        filter.setUrlPatterns(Collections.singleton("/**"));
        // Set ignore url, when multiply the value spilt with ","
        String[] urls = excludesApi.split(",");
        if (!StringUtils.isBlank(contextPath)) {
            if (urls.length > 0) {
                urls = Arrays.stream(urls)
                        .map(it -> contextPath + it)
                        .toArray(String[]::new);
            }
        }
        filter.addInitParameter("excludedUris", StringUtils.join(urls, ","));
        filter.setOrder(Ordered.HIGHEST_PRECEDENCE);
        filter.setFilter(new Security2TokenFilter());
        return filter;
    }
}
