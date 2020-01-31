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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.premiumminds.flowable.conf.KeycloakProperties;

public class OIDCMetadataHolder extends OIDCRequestService {
    private final OIDCProviderMetadata providerMetadata;

    public OIDCMetadataHolder(KeycloakProperties properties) {
        super(properties);

        Issuer issuer = new Issuer(properties.getIssuerUrl());

        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
        // Make HTTP request
        HTTPRequest httpRequest = configureHttpRequest(request.toHTTPRequest());
        try {
            HTTPResponse httpResponse = httpRequest.send();
            providerMetadata = OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());
        } catch (Exception e) {
            throw new RuntimeException("OpenID Connect - error getting issuer '" + issuer + "' metadata", e);
        }
    }

    public OIDCProviderMetadata getProviderMetadata() {
        return providerMetadata;
    }
}
