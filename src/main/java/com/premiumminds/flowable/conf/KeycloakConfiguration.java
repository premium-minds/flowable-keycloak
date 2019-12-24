package com.premiumminds.flowable.conf;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KeycloakProperties.class)
@ComponentScan(basePackages = { "com.premiumminds.flowable.service" })
public class KeycloakConfiguration {
}
