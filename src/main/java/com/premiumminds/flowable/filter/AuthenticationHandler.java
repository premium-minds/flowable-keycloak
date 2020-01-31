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
package com.premiumminds.flowable.filter;

import com.google.common.cache.Cache;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.premiumminds.flowable.conf.KeycloakProperties;
import com.premiumminds.flowable.service.KeycloakAccessTokenExtractor;
import com.premiumminds.flowable.service.OIDCClient;
import com.premiumminds.flowable.service.OIDCMetadataHolder;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.tuple.Pair;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.CookieConstants;
import org.flowable.ui.common.security.FlowableAppUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationHandler.class);

    private final Cache<String, FlowableAppUser> userCache;

    private final Cache<String, RemoteToken> tokenCache;

    private final RemoteIdmService remoteIdmService;

    private final OIDCClient oidcClient;

    private final KeycloakAccessTokenExtractor accessTokenExtractor;

    private final KeycloakCookieFilter filter;

    public AuthenticationHandler(Cache<String, FlowableAppUser> userCache,
            Cache<String, RemoteToken> tokenCache, KeycloakProperties keycloakProperties,
            RemoteIdmService remoteIdmService,
            KeycloakCookieFilter filter) {
        this.userCache = userCache;
        this.tokenCache = tokenCache;
        this.filter = filter;
        this.remoteIdmService = remoteIdmService;

        OIDCMetadataHolder metadataHolder = new OIDCMetadataHolder(keycloakProperties);
        this.oidcClient = new OIDCClient(keycloakProperties, metadataHolder);
        this.accessTokenExtractor = new KeycloakAccessTokenExtractor(keycloakProperties, metadataHolder);
    }

    public URI login() {
        return oidcClient.login();
    }

    public boolean handleAuthenticatedRequest(HttpServletRequest request, HttpServletResponse response) {
        Pair<RemoteToken, FlowableAppUser> userToken = getValidFlowableUser(request, response);
        if (userToken != null) {
            FlowableAppUser appUser = userToken.getValue();
            RemoteToken token = userToken.getKey();
            if (!filter.validateRequiredPrivileges(request, response, appUser)) {
                filter.redirectOrSendNotPermitted(request, response,
                        appUser.getUserObject().getId());
                return false;
            }
            SecurityContextHolder.getContext()
                    .setAuthentication(new RememberMeAuthenticationToken(token.getId(),
                            appUser, appUser.getAuthorities()));

            if (filter.filterCallback != null) {
                filter.filterCallback.onValidTokenFound(request, response, token);
            }
        } else {
            LOGGER.debug("No valid token found.");
            filter.redirectOrSendNotPermitted(request, response, null);
            return false;
        }
        return true;
    }


    public void authenticationCallbackHandler(HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        OIDCTokens tokens = oidcClient.getOIDCTokens(request);
        final BearerAccessToken accessToken = tokens.getBearerAccessToken();
        JWTClaimsSet claims = accessTokenExtractor.extractClaims(accessToken.getValue());
        String userId = accessTokenExtractor.getUserId(claims);

        RemoteUser loggedUser = remoteIdmService.getUser(userId);

        List<String> roles = accessTokenExtractor.getRoles(accessToken.getValue());

        FlowableAppUser appUser = filter.appUserFromRemoteUser(loggedUser, roles);
        RemoteToken token = tokenFromUser(loggedUser, accessToken);
        updateCaches(appUser, token);

        addRememberCookie(token.getId(), response);

        response.sendRedirect(request.getContextPath());
    }

    private Pair<RemoteToken, FlowableAppUser> getValidFlowableUser(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieConstants.COOKIE_NAME.equals(cookie.getName())) {
                    String tokenId = decodeCookie(cookie.getValue());
                    try {
                        RemoteToken token = tokenCache.getIfPresent(tokenId);
                        FlowableAppUser user = null;
                        if (token != null) {
                            user = userCache.getIfPresent(token.getUserId());
                        }
                        if (user == null) {
                            //filter.redirectToLogin(request, response, null);
                            return null;
                        }
                        return Pair.of(token, user);
                    } catch (Exception e) {
                        LOGGER.debug("Could not find token with id {}", tokenId);
                    }
                }
            }
        }
        return null;
    }

    private String decodeCookie(String cookieValue) {
        return new String(Base64.getDecoder().decode(cookieValue.getBytes()));
    }

    private RemoteToken tokenFromUser(RemoteUser user, BearerAccessToken tokenValue) {
        RemoteToken token = new RemoteToken();
        token.setId(UUID.randomUUID().toString());
        token.setUserId(user.getId());
        token.setValue(tokenValue.getValue());
        return token;
    }

    private void updateCaches(FlowableAppUser appUser, RemoteToken token) {
        userCache.put(appUser.getUserObject().getId(), appUser);
        tokenCache.put(token.getId(), token);
    }

    private void addRememberCookie(String cookieValue, HttpServletResponse response) {
        Cookie cookie = new Cookie(CookieConstants.COOKIE_NAME,
                Base64.getEncoder().encodeToString(cookieValue.getBytes()));
        cookie.setPath("/"); // without this flowable does not clean the cookie on logout
        response.addCookie(cookie);
    }

}
