package com.premiumminds.flowable.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.filter.FlowableCookieFilterCallback;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.security.DefaultPrivileges;
import org.flowable.ui.common.security.FlowableAppUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class RolodexCookieFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(RolodexCookieFilter.class);

    protected FlowableCookieFilterCallback filterCallback;

    protected final RemoteIdmService remoteIdmService;

    protected final FlowableCommonAppProperties properties;

    protected String idmAppUrl;

    protected String redirectUrlOnAuthSuccess;

    protected Collection<String> requiredPrivileges;

    public RolodexCookieFilter(RemoteIdmService remoteIdmService,
            FlowableCommonAppProperties properties) {
        this.remoteIdmService = remoteIdmService;
        this.properties = properties;
    }

    @PostConstruct
    protected void initCaches() {
        initIdmAppRedirectUrl();
    }

    protected void initIdmAppRedirectUrl() {
        idmAppUrl = properties.determineIdmAppRedirectUrl();

        redirectUrlOnAuthSuccess = properties.getRedirectOnAuthSuccess();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!skipAuthenticationCheck(request)) {
            RemoteToken token = new RemoteToken();
            token.setId("TOKEN_ID");
            token.setUserId("jcoelho");
            try {
                RemoteUser user = new RemoteUser();
                user.setId("jcoelho");
                user.setFirstName("José");
                user.setLastName("Coelho");
                user.setEmail("jose.coelho@premium-minds.com");
                user.setTenantId("");
                user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
                user.getPrivileges().add("Privilege 1");
                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_MODELER));
                authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_TASK));

                FlowableAppUser appUser = new FlowableAppUser(user, "userId", authorities);

                if (!validateRequiredPriviliges(request, response, appUser)) {
                    redirectOrSendNotPermitted(request, response);
                    return; // no need to execute any other filters
                }
                SecurityContextHolder.getContext()
                        .setAuthentication(new RememberMeAuthenticationToken(token.getId(), appUser,
                                appUser.getAuthorities()));

            } catch (Exception e) {
                LOGGER.trace("Could not set necessary threadlocals for token", e);
                redirectOrSendNotPermitted(request, response);
            }
            if (filterCallback != null) {
                filterCallback.onValidTokenFound(request, response, token);
            }

        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            if (filterCallback != null) {
                filterCallback.onFilterCleanup(request, response);
            }
        }
    }

    protected boolean skipAuthenticationCheck(HttpServletRequest request) {
        return request.getRequestURI().endsWith(".css") ||
                request.getRequestURI().endsWith(".js") ||
                request.getRequestURI().endsWith(".html") ||
                request.getRequestURI().endsWith(".map") ||
                request.getRequestURI().endsWith(".woff") ||
                request.getRequestURI().endsWith(".png") ||
                request.getRequestURI().endsWith(".jpg") ||
                request.getRequestURI().endsWith(".jpeg") ||
                request.getRequestURI().endsWith(".tif") ||
                request.getRequestURI().endsWith(".tiff");
    }

    protected void redirectOrSendNotPermitted(HttpServletRequest request,
            HttpServletResponse response) {
        if (isRootPath(request)) {
            redirectToLogin(request, response);
        } else {
            sendNotPermitted(request, response);
        }
    }

    protected void redirectToLogin(HttpServletRequest request, HttpServletResponse response) {
        try {
            String baseRedirectUrl = idmAppUrl + "#/login?redirectOnAuthSuccess=true&redirectUrl=";
            if (redirectUrlOnAuthSuccess != null) {
                response.sendRedirect(baseRedirectUrl + redirectUrlOnAuthSuccess);

            } else {
                response.sendRedirect(baseRedirectUrl + request.getRequestURL());
            }

        } catch (IOException e) {
            LOGGER.warn("Could not redirect to {}", idmAppUrl, e);
        }
    }

    protected void sendNotPermitted(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    protected boolean isRootPath(HttpServletRequest request) {
        String pathInfo = request.getPathInfo();
        return pathInfo == null || "".equals(pathInfo) || "/".equals(pathInfo);
    }

    protected boolean validateRequiredPriviliges(HttpServletRequest request,
            HttpServletResponse response, FlowableAppUser user) {

        if (user == null) {
            return true;
        }

        String pathInfo = request.getPathInfo();
        if (isRootPath(request) || !pathInfo.startsWith("/rest")) { // rest calls handled by Spring
                                                                    // Security conf

            if (requiredPrivileges != null && requiredPrivileges.size() > 0) {

                if (user.getAuthorities() == null || user.getAuthorities().size() == 0) {
                    return false;
                } else {
                    int matchingPrivileges = 0;
                    for (GrantedAuthority authority : user.getAuthorities()) {
                        if (requiredPrivileges.contains(authority.getAuthority())) {
                            matchingPrivileges++;
                        }
                    }

                    if (matchingPrivileges != requiredPrivileges.size()) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    public void setRequiredPrivileges(Collection<String> requiredPrivileges) {
        this.requiredPrivileges = requiredPrivileges;
    }

    @Autowired(required = false)
    public void setFilterCallback(FlowableCookieFilterCallback filterCallback) {
        this.filterCallback = filterCallback;
    }

}
