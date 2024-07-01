package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider;

import javax.ws.rs.ext.Provider;

@Provider
public class KeycloakClientJacksonProvider extends ResteasyJackson2Provider {
    public KeycloakClientJacksonProvider() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        setMapper(objectMapper);
    }
}
