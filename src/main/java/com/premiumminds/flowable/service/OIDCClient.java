package com.premiumminds.flowable.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.premiumminds.flowable.conf.KeycloakProperties;
import java.net.URI;
import javax.servlet.http.HttpServletRequest;

public class OIDCClient extends OIDCRequestService {
    private final KeycloakProperties properties;

    private final Issuer issuer;

    private final ClientID clientID;

    private final Secret clientSecret;

    private final URI callbackUri;

    private final Scope scope;

    private final OIDCProviderMetadata providerMetadata;

    public OIDCClient(KeycloakProperties properties, OIDCMetadataHolder metadataHolder) {
        super(properties);
        this.properties = properties;

        this.issuer = new Issuer(properties.getIssuerUrl());
        this.clientID = new ClientID(properties.getClient().getClientId());
        this.clientSecret = new Secret(properties.getClient().getClientSecret());
        this.callbackUri = URI.create(properties.getClient().getRedirectUri());
        this.scope = Scope.parse(properties.getClient().getScope());

        this.providerMetadata = metadataHolder.getProviderMetadata();
    }

    public URI login() {
        AuthorizationRequest request = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(scope)
                .redirectionURI(callbackUri)
                .endpointURI(providerMetadata.getAuthorizationEndpointURI())
                .build();

        return request.toURI();
    }

    public OIDCTokens getOIDCTokens(HttpServletRequest request) {
        AuthorizationCode code = extractAuthorizationCode(request);
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callbackUri);
        ClientAuthentication clientAuthentication = new ClientSecretBasic(clientID, clientSecret);

        TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                clientAuthentication, codeGrant);
        HTTPRequest tokenHttpRequest = configureHttpRequest(tokenRequest.toHTTPRequest());
        try {
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenHttpRequest.send());
            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse error = tokenResponse.toErrorResponse();
                throw new RuntimeException("OpenID Connect - error getting token. Message from issuer server\n" +
                        "\tcode: " + error.getErrorObject().getCode() +
                        "\tmessage: " + error.getErrorObject().getDescription());
            }

            OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
            return oidcTokenResponse.getOIDCTokens();
        } catch (Exception e) {
            throw new RuntimeException("OpenID Connect - error getting token", e);
        }
    }

    private AuthorizationCode extractAuthorizationCode(HttpServletRequest request) {
        URI requestUri = URI.create(getFullURL(request));
        try {
            AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(requestUri);
            if (!authorizationResponse.indicatesSuccess()) {
                AuthorizationErrorResponse error = authorizationResponse.toErrorResponse();
                throw new RuntimeException("OpenID Connect - error getting authorization code. Message from issuer server\n" +
                        "\tcode: " + error.getErrorObject().getCode() +
                        "\tmessage: " + error.getErrorObject().getDescription());
            }

            AuthorizationSuccessResponse successResponse = authorizationResponse.toSuccessResponse();
            return successResponse.getAuthorizationCode();
        } catch (ParseException e) {
            throw new RuntimeException("OpenID Connect - error parsing callback request '" +
                    requestUri.toASCIIString() + "'", e);
        }
    }

    public OIDCTokens authenticate(String username, String password) {
        ClientAuthentication clientAuthentication = new ClientSecretPost(new ClientID(username), new Secret(password));
        TokenRequest tokenRequest = new TokenRequest(this.providerMetadata.getTokenEndpointURI(), clientAuthentication,
                new ClientCredentialsGrant());
        HTTPRequest httpRequest = configureHttpRequest(tokenRequest.toHTTPRequest());

        try {
            OIDCTokenResponse response = OIDCTokenResponse.parse(httpRequest.send());
            if (!response.indicatesSuccess()) {
                TokenErrorResponse error = response.toErrorResponse();
                throw new RuntimeException("OpenID Connect - error authenticating client. Message from issuer server\n" +
                        "\tcode: " + error.getErrorObject().getCode() +
                        "\tmessage: " + error.getErrorObject().getDescription());
            }

            return response.getOIDCTokens();
        } catch (Exception e) {
            throw new RuntimeException("OpenID Connect - error authenticating client", e);
        }
    }

    private static String getFullURL(HttpServletRequest request) {
        StringBuilder requestURL = new StringBuilder(request.getRequestURL().toString());
        String queryString = request.getQueryString();

        if (queryString == null) {
            return requestURL.toString();
        } else {
            return requestURL.append('?').append(queryString).toString();
        }
    }
}
