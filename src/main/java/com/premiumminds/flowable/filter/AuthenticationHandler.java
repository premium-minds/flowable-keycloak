package com.premiumminds.flowable.filter;

import com.google.common.cache.LoadingCache;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
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
import java.util.concurrent.ExecutionException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.CookieConstants;
import org.flowable.ui.common.security.FlowableAppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationHandler.class);

    private final LoadingCache<String, FlowableAppUser> userCache;

    private final LoadingCache<String, RemoteToken> tokenCache;

    private final OIDCClient oidcClient;

    private final KeycloakAccessTokenExtractor accessTokenExtractor;

    private final KeycloakCookieFilter filter;

    public AuthenticationHandler(LoadingCache<String, FlowableAppUser> userCache,
            LoadingCache<String, RemoteToken> tokenCache, KeycloakProperties keycloakProperties, KeycloakCookieFilter filter) {
        this.userCache = userCache;
        this.tokenCache = tokenCache;
        this.filter = filter;

        OIDCMetadataHolder metadataHolder = new OIDCMetadataHolder(keycloakProperties);
        this.oidcClient = new OIDCClient(keycloakProperties, metadataHolder);
        this.accessTokenExtractor = new KeycloakAccessTokenExtractor(keycloakProperties, metadataHolder);
    }

    public URI login() {
        return oidcClient.login();
    }

    public boolean handleAuthenticatedRequest(HttpServletRequest request, HttpServletResponse response) {
        RemoteToken token = getValidToken(request, response);
        if (token != null) {
            try {
                FlowableAppUser appUser = userCache.get(token.getUserId());
                if (!filter.validateRequiredPrivileges(request, response, appUser)) {
                    filter.redirectOrSendNotPermitted(request, response,
                            appUser.getUserObject().getId());
                    return false;
                }
                SecurityContextHolder.getContext()
                        .setAuthentication(new RememberMeAuthenticationToken(token.getId(),
                                appUser, appUser.getAuthorities()));

            } catch (ExecutionException e) {
                LOGGER.trace("Could not set necessary threadlocals for token", e);
                filter.redirectOrSendNotPermitted(request, response, token.getUserId());
                return false;
            }
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
        UserInfo userInfo = oidcClient.getUserInfo(accessToken);

        RemoteUser loggedUser = new RemoteUser();
        loggedUser.setId(userInfo.getSubject().getValue());
        loggedUser.setFirstName(userInfo.getGivenName());
        loggedUser.setLastName(userInfo.getFamilyName());
        loggedUser.setFullName(userInfo.getName());
        loggedUser.setEmail(userInfo.getEmailAddress());

        List<String> roles = accessTokenExtractor.getRoles(accessToken.getValue());
        loggedUser.getPrivileges().addAll(roles);

        FlowableAppUser appUser = filter.appUserFromRemoteUser(loggedUser);
        RemoteToken token = tokenFromUser(loggedUser, accessToken);
        updateCaches(appUser, token);

        addRememberCookie(token.getId(), response);

        response.sendRedirect(request.getContextPath());
    }

    private RemoteToken getValidToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieConstants.COOKIE_NAME.equals(cookie.getName())) {
                    String tokenId = decodeCookie(cookie.getValue());
                    try {
                        RemoteToken token = tokenCache.get(tokenId);
                        if (token == null) {
                            filter.redirectToLogin(request, response, null);
                            return null;
                        }
                        return token;
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
