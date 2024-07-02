package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider;

public class KeycloakClientJacksonProvider extends ResteasyJackson2Provider {
    public KeycloakClientJacksonProvider() {
        disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
