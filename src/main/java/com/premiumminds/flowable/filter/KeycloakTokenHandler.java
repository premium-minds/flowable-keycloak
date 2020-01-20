package com.premiumminds.flowable.filter;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.FlowableAppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class KeycloakTokenHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenHandler.class);

    public static final String AUTHORIZATION = "Authorization";

    private final KeycloakCookieFilter filter;

    private final OIDCClient oidcClient;

    public KeycloakTokenHandler(OIDCClient oidcClient,
            KeycloakCookieFilter filter) {
        this.filter = filter;
        this.oidcClient = oidcClient;
    }

    public boolean hasAuthorizationHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION) != null;
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        BearerAccessToken accessToken = getAccessToken(request);
        if (accessToken != null) {
            UserInfo userInfo = oidcClient.getUserInfo(accessToken);
            RemoteUser user = convertUser(userInfo);
            FlowableAppUser appUser = filter.appUserFromRemoteUser(user);
            if (!filter.validateRequiredPrivileges(request, response, appUser)) {
                filter.redirectOrSendNotPermitted(request, response,
                        appUser.getUserObject().getId());
                return false;
            }
            SecurityContextHolder.getContext()
                    .setAuthentication(new RememberMeAuthenticationToken("RUNTIME-USER",
                            appUser, appUser.getAuthorities()));

            if (filter.filterCallback != null) {
                RemoteToken token = new RemoteToken();
                token.setUserId(user.getId());
                filter.filterCallback.onValidTokenFound(request, response, token);
            }
        } else {
            LOGGER.warn("Unauthorized.");
            filter.sendNotPermitted(request, response);
            return false;
        }
        return true;
    }

    private BearerAccessToken getAccessToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION);

        try {
            return BearerAccessToken.parse(header);
        } catch (ParseException e) {
            return null;
        }
    }

    private RemoteUser convertUser(UserInfo userInfo) {
        RemoteUser user = new RemoteUser();
        user.setId(userInfo.getSubject().getValue());
        user.setFirstName(userInfo.getGivenName());
        user.setLastName(userInfo.getFamilyName());
        user.setEmail(userInfo.getEmailAddress());
        return user;
    }
}
