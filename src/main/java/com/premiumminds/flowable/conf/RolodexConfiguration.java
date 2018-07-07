package com.premiumminds.flowable.conf;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = {
        "com.premiumminds.flowable.service"
})
public class RolodexConfiguration {
}
