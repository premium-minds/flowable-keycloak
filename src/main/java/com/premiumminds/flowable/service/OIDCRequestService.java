package com.premiumminds.flowable.service;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.premiumminds.flowable.conf.KeycloakProperties;

public abstract class OIDCRequestService {
    protected final int connectionReadTimeout;

    protected final int connectionConnectTimeout;

    public OIDCRequestService(KeycloakProperties properties) {
        this.connectionConnectTimeout = properties.getConnectTimeout();
        this.connectionReadTimeout = properties.getReadTimeout();
    }

    protected HTTPRequest configureHttpRequest(HTTPRequest req) {
        req.setConnectTimeout(connectionConnectTimeout);
        req.setReadTimeout(connectionReadTimeout);
        return req;
    }
}
