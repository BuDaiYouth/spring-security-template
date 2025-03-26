package xyz.ibudai.security.common.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.filter")
public class FilterProps {

    private Boolean enabled;

    private String[] whiteList;

}
