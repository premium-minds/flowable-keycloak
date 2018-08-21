package com.premiumminds.flowable.conf;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rolodex")
public class RolodexProperties {

    private AppOauthCredentials appOauthCredentials;

    private UserOauthCredentials userOauthCredentials;

    private Endpoints endpoints;

    public AppOauthCredentials getAppAuthCredentials() {
        return appOauthCredentials;
    }

    public void setAppAuthCredentials(AppOauthCredentials appAuthCredentials) {
        this.appOauthCredentials = appAuthCredentials;
    }

    public UserOauthCredentials getUserAuthCredentials() {
        return userOauthCredentials;
    }

    public void setUserAuthCredentials(UserOauthCredentials userAuthCredentials) {
        this.userOauthCredentials = userAuthCredentials;
    }

    public Endpoints getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(Endpoints endpoints) {
        this.endpoints = endpoints;
    }

    public static class AppOauthCredentials {
        private String clientId;

        private String clientSecret;

        private String scope;

        private String redirectUri;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    public static class UserOauthCredentials {
        private String clientId;

        private String clientSecret;

        private String scope;

        private String redirectUri;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    public static class Endpoints {
        private String baseUri;

        private String tokenEndpointUri;

        private String employeesEndpointUri;

        private String workgroupsEndpointUri;

        private String rolesEndpointUri;

        private String authorizeEndpointUri;

        private String employeesMeEndpointUri;

        private String logoutEndpointUri;

        public String getBaseUri() {
            return baseUri;
        }

        public void setBaseUri(String baseUri) {
            this.baseUri = baseUri;
        }

        public URI getTokenEndpointUri() {
            return URI.create(tokenEndpointUri);
        }

        public void setTokenEndpointUri(String tokenEndpointUri) {
            this.tokenEndpointUri = tokenEndpointUri;
        }

        public URI getEmployeesEndpointUri() {
            return URI.create(employeesEndpointUri);
        }

        public void setEmployeesEndpointUri(String employeesEndpointUri) {
            this.employeesEndpointUri = employeesEndpointUri;
        }

        public URI getWorkgroupsEndpointUri() {
            return URI.create(workgroupsEndpointUri);
        }

        public void setWorkgroupsEndpointUri(String workgroupsEndpointUri) {
            this.workgroupsEndpointUri = workgroupsEndpointUri;
        }

        public URI getRolesEndpointUri() {
            return URI.create(rolesEndpointUri);
        }

        public void setRolesEndpointUri(String rolesEndpointUri) {
            this.rolesEndpointUri = rolesEndpointUri;
        }

        public URI getAuthorizeEndpointUri() {
            return URI.create(authorizeEndpointUri);
        }

        public void setAuthorizeEndpointUri(String authorizeEndpointUri) {
            this.authorizeEndpointUri = authorizeEndpointUri;
        }

        public URI getEmployeesMeEndpointUri() {
            return URI.create(employeesMeEndpointUri);
        }

        public void setEmployeesMeEndpointUri(String employeesMeEndpointUri) {
            this.employeesMeEndpointUri = employeesMeEndpointUri;
        }

        public URI getLogoutEndpointUri() {
            return URI.create(logoutEndpointUri);
        }

        public void setLogoutEndpointUri(String logoutEndpointUri) {
            this.logoutEndpointUri = logoutEndpointUri;
        }

    }
}
