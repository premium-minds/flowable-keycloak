package com.premiumminds.flowable.filter;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.premiumminds.flowable.conf.RolodexProperties;
import com.premiumminds.flowable.service.RolodexApi;
import com.premiumminds.flowable.service.RolodexApi.AuthorizationType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.flowable.ui.common.filter.FlowableCookieFilterCallback;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.security.CookieConstants;
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

    private static final int MAX_CACHE_SIZE = 100;

    private static final int MAX_CACHE_DURATION_MINUTES = 55;

    protected FlowableCookieFilterCallback filterCallback;

    protected final RemoteIdmService remoteIdmService;

    protected final FlowableCommonAppProperties properties;

    private RolodexApi rolodex;

    protected Collection<String> requiredPrivileges;

    protected LoadingCache<String, FlowableAppUser> userCache;

    protected LoadingCache<String, RemoteToken> tokenCache;

    public RolodexCookieFilter(RemoteIdmService remoteIdmService,
            FlowableCommonAppProperties properties, RolodexProperties rolodexProperties) {
        this.remoteIdmService = remoteIdmService;
        this.properties = properties;
        rolodex = new RolodexApi(rolodexProperties, AuthorizationType.AUTHORIZATION_CODE);
    }

    @PostConstruct
    protected void initCaches() {
        initUserCache();
        initTokenCache();
    }

    protected void initUserCache() {

        userCache = CacheBuilder.newBuilder().maximumSize(MAX_CACHE_SIZE)
                .expireAfterWrite(MAX_CACHE_DURATION_MINUTES, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, FlowableAppUser>() {

                    @Override
                    public FlowableAppUser load(String userId) throws Exception {
                        LOGGER.info("user cache load invoked.");
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
                .expireAfterWrite(MAX_CACHE_DURATION_MINUTES, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, RemoteToken>() {

                    @Override
                    public RemoteToken load(String tokenId) throws Exception {
                        LOGGER.info("token cache load invoked.");
                        // must never reach here directly.
                        return null;
                    }
                });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (rolodexAuthenticationCallbackCheck(request)) {
            rolodexAuthenticationCallbackHandler(request, response);
            return; // no need to execute extra filters
        }

        if (!skipAuthenticationCheck(request)) {
            RemoteToken token = getValidToken(request, response);
            if (token != null) {
                try {
                    FlowableAppUser appUser = userCache.get(token.getUserId());
                    if (!validateRequiredPriviliges(request, response, appUser)) {
                        redirectOrSendNotPermitted(request, response,
                                appUser.getUserObject().getId());
                        return; // no need to execute any other filters
                    }
                    SecurityContextHolder.getContext()
                            .setAuthentication(new RememberMeAuthenticationToken(token.getId(),
                                    appUser, appUser.getAuthorities()));

                } catch (ExecutionException e) {
                    LOGGER.trace("Could not set necessary threadlocals for token", e);
                    redirectOrSendNotPermitted(request, response, token.getUserId());
                }
                if (filterCallback != null) {
                    filterCallback.onValidTokenFound(request, response, token);
                }
            } else {
                LOGGER.info("No valid token found.");
                redirectOrSendNotPermitted(request, response, null);
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

    private RemoteToken getValidToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieConstants.COOKIE_NAME.equals(cookie.getName())) {
                    String tokenId = decodeCookie(cookie.getValue());
                    try {
                        RemoteToken token = tokenCache.get(tokenId);
                        if (token == null) {
                            redirectToLogin(request, response, null);
                            return null;
                        }
                        return token;
                    } catch (Exception e) {
                        LOGGER.warn("Could not find token with id {}", tokenId);
                    }
                }
            }
        }
        return null;
    }

    private String decodeCookie(String cookieValue) {
        return new String(Base64.getDecoder().decode(cookieValue.getBytes()));
    }

    protected boolean rolodexAuthenticationCallbackCheck(HttpServletRequest request) {
        return request.getRequestURL().toString().equals(rolodex.getRedirectUrl());
    }

    protected void rolodexAuthenticationCallbackHandler(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        LOGGER.info("Rolodex Authentication Callback");
        String oauthTokenValue = rolodex.getOauth2TokenFromAuthCode(request);
        RemoteUser loggedUser = getLoggedUser(oauthTokenValue);
        FlowableAppUser appUser = appUserFromRemoteUser(loggedUser);
        RemoteToken token = tokenFromUser(loggedUser, oauthTokenValue);
        updateCaches(appUser, token);
        addRolodexRememberCookie(token.getId(), response);
        response.sendRedirect("http://localhost:8888/flowable-modeler");
    }

    protected RemoteUser getLoggedUser(String oauthTokenValue) throws IOException {
        RemoteUser loggedUser = rolodex.getMe(oauthTokenValue);
        loggedUser.setTenantId("");
        // loggedUser.getPrivileges().add("....");
        return loggedUser;
    }

    protected FlowableAppUser appUserFromRemoteUser(RemoteUser user) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_MODELER));
        // authorities.add(new SimpleGrantedAuthority(DefaultPrivileges.ACCESS_TASK));
        FlowableAppUser appUser = new FlowableAppUser(user, user.getId(), authorities);
        return appUser;
    }

    protected RemoteToken tokenFromUser(RemoteUser user, String tokenValue) {
        RemoteToken token = new RemoteToken();
        token.setId(UUID.randomUUID().toString());
        token.setUserId(user.getId());
        token.setValue(tokenValue);
        return token;
    }

    protected void updateCaches(FlowableAppUser appUser, RemoteToken token) {
        userCache.put(appUser.getUserObject().getId(), appUser);
        tokenCache.put(token.getId(), token);
    }

    protected void addRolodexRememberCookie(String cookieValue, HttpServletResponse response) {
        Cookie cookie = new Cookie(CookieConstants.COOKIE_NAME,
                Base64.getEncoder().encodeToString(cookieValue.getBytes()));
        cookie.setPath("/"); // without this flowable does not clean the cookie on logout
        response.addCookie(cookie);
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
        rolodex.redirectToLogin(response);
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
