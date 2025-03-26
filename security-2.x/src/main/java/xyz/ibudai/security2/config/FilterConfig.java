package xyz.ibudai.security2.config;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import xyz.ibudai.security.common.props.FilterProps;
import xyz.ibudai.security2.filter.Security2TokenFilter;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class FilterConfig {

    private final FilterProps filterProps;
    private final Security2TokenFilter security2TokenFilter;


    @Bean
    public FilterRegistrationBean<Security2TokenFilter> orderFilter1() {
        FilterRegistrationBean<Security2TokenFilter> filter = new FilterRegistrationBean<>();
        filter.setName("auth-filter");

        // Set effect url
        filter.setUrlPatterns(Collections.singleton("/**"));

        // Set whitelist
        String urls = StringUtils.join(filterProps.getWhiteList(), ",");
        filter.addInitParameter("excludedUris", urls);
        filter.setOrder(Ordered.HIGHEST_PRECEDENCE);
        filter.setFilter(security2TokenFilter);
        return filter;
    }
}
