/**
 * Copyright (C) 2020 Premium Minds.
 *
 * This file is part of Flowable Keycloak.
 *
 * Flowable Keycloak is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Flowable Keycloak is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Flowable Keycloak. If not, see <http://www.gnu.org/licenses/>.
 */
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
