package com.premiumminds.flowable.filter;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.premiumminds.flowable.conf.KeycloakProperties;
import com.premiumminds.flowable.service.KeycloakServiceImpl;
import com.premiumminds.flowable.service.RemoteIdmApi;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.filter.FlowableCookieFilterCallback;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.security.DefaultPrivileges;
import org.flowable.ui.common.security.FlowableAppUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

@Primary
@Service
public class KeycloakCookieFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakCookieFilter.class);

    private static final int MAX_CACHE_SIZE = 100;

    private static final int MAX_CACHE_DURATION_DAYS = 1;

    protected FlowableCookieFilterCallback filterCallback;

    protected final RemoteIdmService remoteIdmService;

    protected final FlowableCommonAppProperties properties;

    private RemoteIdmApi remoteIdmApi;

    private OIDCClient oidcClient;

    protected Collection<String> requiredPrivileges;

    protected LoadingCache<String, FlowableAppUser> userCache;

    protected LoadingCache<String, RemoteToken> tokenCache;

    protected ImpersonationHandler impersonationHandler;

    protected AuthenticationHandler authenticationHandler;

    public KeycloakCookieFilter(RemoteIdmService remoteIdmService,
            FlowableCommonAppProperties properties, KeycloakProperties keycloakProperties) {
        this.remoteIdmService = remoteIdmService;
        this.properties = properties;

        remoteIdmApi = new KeycloakServiceImpl(keycloakProperties);
        oidcClient = new OIDCClient(keycloakProperties);

        impersonationHandler = new ImpersonationHandler(properties.getIdmAdmin().getUser(),
                properties.getIdmAdmin().getPassword(), remoteIdmService, this);

        initUserCache();
        initTokenCache();

        authenticationHandler = new AuthenticationHandler(userCache, tokenCache, oidcClient, this);

    }

    protected void initUserCache() {

        userCache = CacheBuilder.newBuilder().maximumSize(MAX_CACHE_SIZE)
                .expireAfterWrite(MAX_CACHE_DURATION_DAYS, TimeUnit.DAYS).recordStats()
                .build(new CacheLoader<String, FlowableAppUser>() {

                    @Override
                    public FlowableAppUser load(String userId) throws Exception {
                        RemoteUser user = remoteIdmService.getUser(userId);
                        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                        for (String privilege : user.getPrivileges()) {
                            grantedAuthorities.add(new SimpleGrantedAuthority(privilege));
                        }
                        FlowableAppUser appUser =
                                new FlowableAppUser(user, user.getId(), grantedAuthorities);
                        return appUser;
                    }
                });
    }

    protected void initTokenCache() {

        tokenCache = CacheBuilder.newBuilder().maximumSize(MAX_CACHE_SIZE)
                .expireAfterWrite(MAX_CACHE_DURATION_DAYS, TimeUnit.DAYS).recordStats()
                .build(new CacheLoader<String, RemoteToken>() {

                    @Override
                    public RemoteToken load(String tokenId) throws Exception {
                        // must never reach here directly.
                        return null;
                    }
                });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (isAuthenticationCallbackRequest(request)) {
            authenticationHandler.authenticationCallbackHandler(request, response);
            return; // no need to execute extra filters
        }

        if (!skipAuthenticationCheck(request)) {
            if (impersonationHandler.checkImpersonationHeaders(request)) {
                if (!impersonationHandler.handleImpersonatedRequest(request, response)) {
                    return; // no need to execute extra filters
                }
            } else {
                if (!authenticationHandler.handleAuthenticatedRequest(request, response)) {
                    return; // no need to execute any other filters
                }
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

    protected boolean isAuthenticationCallbackRequest(HttpServletRequest request) {
        return request.getRequestURI().equals(request.getContextPath() + "/callback");
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
            HttpServletResponse response, String userId) {
        if (isRootPath(request)) {
            redirectToLogin(request, response, userId);
        } else {
            sendNotPermitted(request, response);
        }
    }

    protected void redirectToLogin(HttpServletRequest request, HttpServletResponse response,
            String userId) {
        if (userId != null) {
            userCache.invalidate(userId);
        }
        try {
            response.sendRedirect(oidcClient.login().toASCIIString());
        } catch (IOException e) {
            throw new RuntimeException("error redirecting user to oidc login", e);
        }
    }

    protected void sendNotPermitted(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    protected boolean isRootPath(HttpServletRequest request) {
        String pathInfo = request.getPathInfo();
        return pathInfo == null || "".equals(pathInfo) || "/".equals(pathInfo);
    }

    protected FlowableAppUser appUserFromRemoteUser(RemoteUser user) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_MODELER));
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_TASK));
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_REST_API));
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_ADMIN));
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_IDM));

        FlowableAppUser appUser = new FlowableAppUser(user, user.getId(), authorities);
        return appUser;
    }

    protected boolean validateRequiredPrivileges(HttpServletRequest request,
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
