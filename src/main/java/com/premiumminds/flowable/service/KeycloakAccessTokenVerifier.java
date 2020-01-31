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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.AbstractJWTValidator;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import java.time.Instant;
import java.util.Date;

public class KeycloakAccessTokenVerifier implements JWTClaimsSetVerifier<SecurityContext>, ClockSkewAware {
    /**
     * The expected ID token issuer.
     */
    private final Issuer expectedIssuer;


    /**
     * The expected nonce, {@code null} if not required or specified.
     */
    private final Nonce expectedNonce;


    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private int maxClockSkew = AbstractJWTValidator.DEFAULT_MAX_CLOCK_SKEW;

    public KeycloakAccessTokenVerifier(Issuer issuer, ClientID clientID, Nonce nonce) {
        if (issuer == null) {
            throw new IllegalArgumentException("The expected ID token issuer must not be null");
        }
        this.expectedIssuer = issuer;

        if (clientID == null) {
            throw new IllegalArgumentException("The client ID must not be null");
        }
        this.expectedNonce = nonce;
    }

    @Override
    public int getMaxClockSkew() {
        return maxClockSkew;
    }

    @Override
    public void setMaxClockSkew(int maxClockSkewSeconds) {
        this.maxClockSkew = maxClockSkewSeconds;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        final String tokenIssuer = claimsSet.getIssuer();

        if (tokenIssuer == null) {
            throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
        }

        if (!expectedIssuer.getValue().equals(tokenIssuer)) {
            throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
        }

        if (claimsSet.getSubject() == null) {
            throw BadJWTExceptions.MISSING_SUB_CLAIM_EXCEPTION;
        }

        final String tokenAzp;

        try {
            tokenAzp = claimsSet.getStringClaim("azp");
        } catch (java.text.ParseException e) {
            throw new BadJWTException("Invalid JWT authorized party (azp) claim: " + e.getMessage());
        }

        final Date exp = claimsSet.getExpirationTime();

        if (exp == null) {
            throw BadJWTExceptions.MISSING_EXP_CLAIM_EXCEPTION;
        }

        final Date iat = claimsSet.getIssueTime();

        if (iat == null) {
            throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION;
        }


        final Date nowRef = Date.from(Instant.now());

        // Expiration must be after current time, given acceptable clock skew
        if (!DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
            throw BadJWTExceptions.EXPIRED_EXCEPTION;
        }

        // Issue time must be before current time, given acceptable clock skew
        if (!DateUtils.isBefore(iat, nowRef, maxClockSkew)) {
            throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION;
        }


        if (expectedNonce != null) {

            final String tokenNonce;

            try {
                tokenNonce = claimsSet.getStringClaim("nonce");
            } catch (java.text.ParseException e) {
                throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + e.getMessage());
            }

            if (tokenNonce == null) {
                throw BadJWTExceptions.MISSING_NONCE_CLAIM_EXCEPTION;
            }

            if (!expectedNonce.getValue().equals(tokenNonce)) {
                throw new BadJWTException("Unexpected JWT nonce (nonce) claim: " + tokenNonce);
            }
        }

    }
}
