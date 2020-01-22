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
