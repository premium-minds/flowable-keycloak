package com.premiumminds.flowable.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.premiumminds.flowable.conf.KeycloakProperties;
import com.premiumminds.flowable.service.KeycloakAccessTokenExtractor;
import com.premiumminds.flowable.service.OIDCMetadataHolder;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.FlowableAppUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class KeycloakTokenHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenHandler.class);

    public static final String AUTHORIZATION = "Authorization";

    private final KeycloakCookieFilter filter;

    private final KeycloakAccessTokenExtractor accessTokenExtractor;

    private final RemoteIdmService remoteIdmService;

    public KeycloakTokenHandler(KeycloakProperties keycloakProperties,
            KeycloakCookieFilter filter, RemoteIdmService remoteIdmService) {
        this.filter = filter;
        this.remoteIdmService = remoteIdmService;

        OIDCMetadataHolder metadataHolder = new OIDCMetadataHolder(keycloakProperties);
        this.accessTokenExtractor = new KeycloakAccessTokenExtractor(keycloakProperties, metadataHolder);
    }

    public boolean hasAuthorizationHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION) != null;
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        BearerAccessToken accessToken = getAccessToken(request);
        if (accessToken != null) {
            JWTClaimsSet claims = accessTokenExtractor.extractClaims(accessToken.getValue());
            String userId = accessTokenExtractor.getUserId(claims);

            RemoteUser user = remoteIdmService.getUser(userId);

            List<String> roles = accessTokenExtractor.getRoles(claims);
            user.getPrivileges().addAll(roles);

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
}
