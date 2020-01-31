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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.premiumminds.flowable.conf.KeycloakProperties;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

public class KeycloakAccessTokenExtractor {
    private final ClientID clientId;

    private final OIDCProviderMetadata providerMetadata;

    private final JWKSet jwkSet;

    public KeycloakAccessTokenExtractor(KeycloakProperties keycloakProperties,
            OIDCMetadataHolder metadataHolder) {
        this.clientId = new ClientID(keycloakProperties.getClient().getClientId());
        this.providerMetadata = metadataHolder.getProviderMetadata();

        DefaultResourceRetriever retriever = new DefaultResourceRetriever(keycloakProperties.getConnectTimeout(),
                keycloakProperties.getReadTimeout());

        try {
            String json = retriever.retrieveResource(providerMetadata.getJWKSetURI().toURL()).getContent();
            jwkSet = JWKSet.parse(json);
        } catch (IOException | ParseException e) {
            throw new RuntimeException("problem retrieving jwk sets from keycloak", e);
        }
    }

    public List<String> getRoles(String accessToken) {
        JWTClaimsSet claims = extractClaims(accessToken);
        return getRoles(claims);
    }

    public List<String> getRoles(JWTClaimsSet claims) {
        List<String> roles = new ArrayList<>();
        try {
            JSONObject resourceAccess = claims.getJSONObjectClaim("resource_access");
            if (resourceAccess != null) {
                // get resource access for this client
                String clientId = this.clientId.getValue();
                JSONObject clientResourcesAccess = (JSONObject) resourceAccess.get(clientId);
                if (clientResourcesAccess != null) {
                    // get roles
                    JSONArray clientRoles = (JSONArray) clientResourcesAccess.get("roles");
                    if (clientRoles != null) {
                        clientRoles.forEach(r -> roles.add(r.toString()));
                    }
                }
            }
        } catch (ParseException e) {
            throw new RuntimeException("problem retrieving access token roles", e);
        }
        return roles;
    }

    public String getUserId(JWTClaimsSet claims) {
        return claims.getSubject();
    }

    public JWTClaimsSet extractClaims(String accessToken) {
        try {
            JWT jwt = JWTParser.parse(accessToken);

            Algorithm algorithm = jwt.getHeader().getAlgorithm();
            if (!(algorithm instanceof JWSAlgorithm)) {
                throw new RuntimeException("keycloak access token needs a JWSAlgorithm");
            }

            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>((JWSAlgorithm) algorithm,
                    new ImmutableJWKSet<>(jwkSet));
            jwtProcessor.setJWSKeySelector(keySelector);
            KeycloakAccessTokenVerifier verifier =
                    new KeycloakAccessTokenVerifier(providerMetadata.getIssuer(), clientId,
                            null);
            jwtProcessor.setJWTClaimsSetVerifier(verifier);

            return jwtProcessor.process(jwt, null);
        } catch (ParseException e) {
            throw new RuntimeException("problem parsing access token", e);
        } catch (JOSEException e) {
            throw new RuntimeException("problem parsing access token", e);
        } catch (BadJOSEException e) {
            throw new RuntimeException("problem parsing access token", e);
        }
    }
}
