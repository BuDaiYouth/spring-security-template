package xyz.ibudai.security.common.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.security")
public class SecurityProps {

    private String loginUrl;

    private String logoutUrl;

    private String logoutSuccessUrl;

    private String[] ignoreUrls;

    private String[] commonUrls;

    private String[] userUrls;

    private String[] adminUrls;
}
