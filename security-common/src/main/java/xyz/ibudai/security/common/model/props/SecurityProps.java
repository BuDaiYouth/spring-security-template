package xyz.ibudai.security.common.model.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.security")
public class SecurityProps {

    private String loginUrl;

    private String ignoreUrls;

    private String whitelist;

    private String userUrls;

    private String adminUrls;
}
