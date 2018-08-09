package com.premiumminds.flowable.conf;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rolodex")
public class RolodexProperties {

    private AppAuthCredentials appAuthCredentials;

    private UserAuthCredentials userAuthCredentials;

    private Endpoints endpoints;

    public AppAuthCredentials getAppAuthCredentials() {
        return appAuthCredentials;
    }

    public void setAppAuthCredentials(AppAuthCredentials appAuthCredentials) {
        this.appAuthCredentials = appAuthCredentials;
    }

    public UserAuthCredentials getUserAuthCredentials() {
        return userAuthCredentials;
    }

    public void setUserAuthCredentials(UserAuthCredentials userAuthCredentials) {
        this.userAuthCredentials = userAuthCredentials;
    }

    public Endpoints getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(Endpoints endpoints) {
        this.endpoints = endpoints;
    }

    public static class AppAuthCredentials {
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

    public static class UserAuthCredentials {
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

        public String getTokenEndpointUri() {
            return tokenEndpointUri;
        }

        public void setTokenEndpointUri(String tokenEndpointUri) {
            this.tokenEndpointUri = tokenEndpointUri;
        }

        public String getEmployeesEndpointUri() {
            return employeesEndpointUri;
        }

        public void setEmployeesEndpointUri(String employeesEndpointUri) {
            this.employeesEndpointUri = employeesEndpointUri;
        }

        public String getWorkgroupsEndpointUri() {
            return workgroupsEndpointUri;
        }

        public void setWorkgroupsEndpointUri(String workgroupsEndpointUri) {
            this.workgroupsEndpointUri = workgroupsEndpointUri;
        }

        public String getRolesEndpointUri() {
            return rolesEndpointUri;
        }

        public void setRolesEndpointUri(String rolesEndpointUri) {
            this.rolesEndpointUri = rolesEndpointUri;
        }

        public String getAuthorizeEndpointUri() {
            return authorizeEndpointUri;
        }

        public void setAuthorizeEndpointUri(String authorizeEndpointUri) {
            this.authorizeEndpointUri = authorizeEndpointUri;
        }

        public String getEmployeesMeEndpointUri() {
            return employeesMeEndpointUri;
        }

        public void setEmployeesMeEndpointUri(String employeesMeEndpointUri) {
            this.employeesMeEndpointUri = employeesMeEndpointUri;
        }

        public String getLogoutEndpointUri() {
            return logoutEndpointUri;
        }

        public void setLogoutEndpointUri(String logoutEndpointUri) {
            this.logoutEndpointUri = logoutEndpointUri;
        }

    }
}
