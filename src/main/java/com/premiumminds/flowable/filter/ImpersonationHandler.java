package com.premiumminds.flowable.filter;

import java.nio.charset.Charset;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.FlowableAppUser;
import org.flowable.ui.common.service.exception.NotFoundException;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class ImpersonationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ImpersonationHandler.class);

    public static final String USER_IMPERSONATION_UID = "User-Impersonation-Uid";

    public static final String AUTHORIZATION = "Authorization";

    protected final String adminUser;

    protected final String adminPassword;

    protected final RemoteIdmService remoteIdmService;

    protected final KeycloakCookieFilter filter;

    public ImpersonationHandler(String adminUser, String adminPassword, RemoteIdmService remoteIdmService,
            KeycloakCookieFilter filter) {
        this.adminUser = adminUser;
        this.adminPassword = adminPassword;
        this.remoteIdmService = remoteIdmService;
        this.filter = filter;
    }

    public boolean handleImpersonatedRequest(HttpServletRequest request, HttpServletResponse response) {
        if (checkValidAuthHeaderCredentials(request)) {

            RemoteUser user = getUserFromImpersonationHeader(request);
            if (user != null) {
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
                LOGGER.warn("User not found.");
                filter.sendNotPermitted(request, response);
            }
        } else {
            LOGGER.warn("Unauthorized.");
            filter.sendNotPermitted(request, response);
            return false;
        }
        return true;
    }

    public boolean checkImpersonationHeaders(HttpServletRequest request) {

        if (request.getHeader(AUTHORIZATION) != null &&
                request.getHeader(USER_IMPERSONATION_UID) != null) {
            return true;
        }
        return false;
    }

    private boolean checkValidAuthHeaderCredentials(HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization.startsWith("Basic ")) {
            String auth = authorization.substring("Basic".length()).trim();

            try {
                String authorizationPlainText =
                        new String(Base64.getDecoder().decode(auth), Charset.forName("UTF-8"));
                String[] credentials = authorizationPlainText.split(":", 2);
                if (credentials[0].equals(adminUser) && credentials[1].equals(adminPassword)) {
                    return true;
                }
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Bad format on Authorization header.");
                return false;
            }

        }
        return false;
    }

    private RemoteUser getUserFromImpersonationHeader(HttpServletRequest request) {
        try {
            return remoteIdmService.getUser(request.getHeader(USER_IMPERSONATION_UID));
        } catch (NotFoundException e) {
            return null;
        }
    }

}
