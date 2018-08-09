package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.premiumminds.flowable.conf.RolodexProperties;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RolodexApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(RolodexApi.class);

    private Optional<OAuth2Token> token; // only used to client_credentials

    private final ObjectMapper mapper;

    private RolodexProperties rolodexProperties;

    private String authType;

    public RolodexApi(RolodexProperties rolodexProperties, String authType) {
        mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                false);
        token = Optional.empty();
        this.rolodexProperties = rolodexProperties;
        if (AuthorizationType.validAuthType(authType)) {
            this.authType = authType;
        } else {
            throw new NotImplementedException("Auth type '" + authType + "' not implemented.");
        }
    }

    private OAuth2Token getOauth2Token() throws IOException {
        if (authType.equals(AuthorizationType.CLIENT_CREDENTIALS)) {
            if (!token.isPresent() || token.get().isExpired()) {
                LOGGER.info("OAuth2Token not present or expired, getting a new one.");
                token = Optional.of(getClientCredentialsToken());
            }
            return token.get();
        } else {
            throw new RuntimeException("Bad authorization type ['" + authType + "']");
        }
    }

    private OAuth2Token getClientCredentialsToken() throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = getClientCredentialsOauth2TokenRequest();

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JsonNode node = mapper.readTree(jsonString);
                return OAuth2Token.fromJsonNode(node);
            } else {
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpPost getClientCredentialsOauth2TokenRequest() {
        try {
            URIBuilder uriBuilder =
                    new URIBuilder(rolodexProperties.getEndpoints().getTokenEndpointUri());
            HttpPost post = new HttpPost(uriBuilder.build());
            post.setEntity(new UrlEncodedFormEntity(generateClientCredentialsRequestParams()));
            generateClientCredentialsRequestHeaders(post);
            return post;
        } catch (UnsupportedEncodingException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private List<NameValuePair> generateClientCredentialsRequestParams() {
        List<NameValuePair> rparams = new ArrayList<>(3);
        rparams.add(new BasicNameValuePair("scope",
                rolodexProperties.getAppAuthCredentials().getScope()));
        rparams.add(new BasicNameValuePair("redirect_uri",
                rolodexProperties.getAppAuthCredentials().getRedirectUri()));
        rparams.add(new BasicNameValuePair("grant_type", "client_credentials"));
        return rparams;
    }

    private void generateClientCredentialsRequestHeaders(HttpPost post) {
        post.addHeader(HttpHeaders.AUTHORIZATION,
                "Basic " + new String(Base64.getEncoder()
                        .encode((rolodexProperties.getAppAuthCredentials().getClientId() + ":" +
                                rolodexProperties.getAppAuthCredentials().getClientSecret())
                                        .getBytes(Charset.forName("UTF-8")))));
        post.addHeader(HttpHeaders.CONTENT_TYPE,
                ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        post.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    private OAuth2Token getAuthorizationCodeToken(String authCode) throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost request = getAuthorizationCodeOauth2TokenRequest(authCode);

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JsonNode node = mapper.readTree(jsonString);
                return OAuth2Token.fromJsonNode(node);
            } else {
                LOGGER.error(EntityUtils.toString(response.getEntity()));
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpPost getAuthorizationCodeOauth2TokenRequest(String authCode) {
        try {
            URIBuilder uriBuilder =
                    new URIBuilder(rolodexProperties.getEndpoints().getTokenEndpointUri());
            HttpPost post = new HttpPost(uriBuilder.build());
            post.setEntity(
                    new UrlEncodedFormEntity(generateAuthorizationCodeRequestParams(authCode)));
            generateAuthorizationCodeRequestHeaders(post);
            return post;
        } catch (UnsupportedEncodingException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private List<NameValuePair> generateAuthorizationCodeRequestParams(String authCode) {
        List<NameValuePair> rparams = new ArrayList<>(4);
        rparams.add(new BasicNameValuePair("scope",
                rolodexProperties.getUserAuthCredentials().getScope()));
        rparams.add(new BasicNameValuePair("redirect_uri",
                rolodexProperties.getUserAuthCredentials().getRedirectUri()));
        rparams.add(new BasicNameValuePair("grant_type", "authorization_code"));
        rparams.add(new BasicNameValuePair("code", authCode));
        return rparams;
    }

    private void generateAuthorizationCodeRequestHeaders(HttpPost post) {
        post.addHeader(HttpHeaders.AUTHORIZATION,
                "Basic " + new String(Base64.getEncoder()
                        .encode((rolodexProperties.getUserAuthCredentials().getClientId() + ":" +
                                rolodexProperties.getUserAuthCredentials().getClientSecret())
                                        .getBytes(Charset.forName("UTF-8")))));
        post.addHeader(HttpHeaders.CONTENT_TYPE,
                ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        post.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    public List<RemoteUser> getEmployees() throws IOException {
        LOGGER.info("getEmployees()");
        OAuth2Token token = getOauth2Token();
        Map<String, String> workgroups = new HashMap<>();
        Map<String, String> roles = new HashMap<>();

        HttpGet request =
                getGetRequest(rolodexProperties.getEndpoints().getEmployeesEndpointUri(), token);
        CloseableHttpClient client = HttpClients.createDefault();

        List<RemoteUser> employees = new ArrayList<>();

        // Load workgroups and roles maps only once for all users
        loadWorkgroupsRolesMaps(token, workgroups, roles);

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JsonNode node = mapper.readTree(jsonString);
                for (JsonNode elem : node) {
                    employees.add(remoteUserFromJsonNode(elem, workgroups, roles));
                }
            } else {
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return employees;
    }

    public RemoteUser getMe(String tokenValue) throws IOException {
        LOGGER.info("getMe()");
        Map<String, String> workgroups = new HashMap<>();
        Map<String, String> roles = new HashMap<>();
        OAuth2Token token = new OAuth2Token(tokenValue, "Bearer");
        HttpGet request =
                getGetRequest(rolodexProperties.getEndpoints().getEmployeesMeEndpointUri(), token);
        CloseableHttpClient client = HttpClients.createDefault();

        // Load workgroups and roles maps only once for all users
        loadWorkgroupsRolesMaps(token, workgroups, roles);

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JsonNode node = mapper.readTree(jsonString);
                return remoteUserFromJsonNode(node, workgroups, roles);
            } else {
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void loadWorkgroupsRolesMaps(OAuth2Token token, Map<String, String> workgroups,
            Map<String, String> roles) throws IOException {
        JsonNode workgroupsJson = getWorkgroups(token);
        JsonNode rolesJson = getRoles(token);

        for (JsonNode elem : workgroupsJson) {
            workgroups.put(elem.get("uid").asText(), elem.get("name").asText());
        }

        for (JsonNode elem : rolesJson) {
            roles.put(elem.get("uid").asText(), elem.get("name").asText());
        }
    }

    public List<RemoteGroup> getGroups() throws IOException {
        LOGGER.info("getGroups()");
        OAuth2Token token = getOauth2Token();

        List<RemoteGroup> groups = new ArrayList<>();
        JsonNode workgroupsJson = getWorkgroups(token);
        JsonNode rolesJson = getRoles(token);
        Map<String, String> rolesUidNameMap = new HashMap<>();

        for (JsonNode elem : rolesJson) {
            groups.add(remoteGroupFromJsonNode("R", elem));
            rolesUidNameMap.put(elem.get("uid").asText(), elem.get("name").asText());
        }

        for (JsonNode elem : workgroupsJson) {
            groups.add(remoteGroupFromJsonNode("W", elem));
            groups.addAll(remoteGroupFromWorkgroupRolePair(elem, rolesUidNameMap));
        }
        return groups;
    }

    private List<RemoteGroup> remoteGroupFromWorkgroupRolePair(JsonNode workgroupElem,
            Map<String, String> rolesUidNameMap) {

        List<RemoteGroup> pairs = new ArrayList<>();

        JsonNode employees = workgroupElem.get("employees");
        Set<String> employeesRoles = new HashSet<>();
        for (JsonNode employee : employees) {
            employeesRoles.add(employee.get("uidRole").asText());
        }

        for (String roleId : employeesRoles) {
            String workgroupRolePairId = "W" + workgroupElem.get("uid").asText() + ":R" + roleId;
            String workgroupRolePairName =
                    workgroupElem.get("name").asText() + " - " + rolesUidNameMap.get(roleId);
            RemoteGroup group = new RemoteGroup();
            group.setId(workgroupRolePairId);
            group.setName(workgroupRolePairName);
            pairs.add(group);
        }
        return pairs;
    }

    private JsonNode getWorkgroups(OAuth2Token token) throws IOException {
        HttpGet request =
                getGetRequest(rolodexProperties.getEndpoints().getWorkgroupsEndpointUri(), token);
        CloseableHttpClient client = HttpClients.createDefault();

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return mapper.readTree(jsonString);
            } else {
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private JsonNode getRoles(OAuth2Token token) throws IOException {
        HttpGet request =
                getGetRequest(rolodexProperties.getEndpoints().getRolesEndpointUri(), token);
        CloseableHttpClient client = HttpClients.createDefault();

        try (CloseableHttpResponse response = client.execute(request)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return mapper.readTree(jsonString);
            } else {
                throw new RuntimeException("Got error response from rolodex. Code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpGet getGetRequest(String uri, OAuth2Token token) {
        HttpGet request = new HttpGet(uri);
        request.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
        request.addHeader(HttpHeaders.AUTHORIZATION, token.getType() + " " + token.getToken());
        return request;
    }

    private RemoteUser remoteUserFromJsonNode(JsonNode node, Map<String, String> workgroups,
            Map<String, String> roles) {
        RemoteUser user = new RemoteUser();
        user.setEmail(node.get("email").asText());
        user.setFirstName(node.get("firstName").asText());
        user.setLastName(node.get("surname").asText());
        user.setFullName(node.get("firstName").asText() + " " + node.get("surname").asText());
        user.setId(node.get("uid").asText());

        JsonNode employeeWorkgroups = node.get("workgroups");
        for (JsonNode workgroup : employeeWorkgroups) {

            String workgroupId = workgroup.get("uidWorkgroup").asText();
            String roleId = workgroup.get("uidRole").asText();
            String workgroupName = workgroups.get(workgroupId);
            String roleName = roles.get(roleId);

            user.getGroups().add(new RemoteGroup("W" + workgroupId, workgroupName));
            user.getGroups().add(new RemoteGroup("R" + roleId, roleName));
            user.getGroups().add(new RemoteGroup("W" + workgroupId + ":R" + roleId,
                    workgroupName + " - " + roleName));
        }
        return user;
    }

    private RemoteGroup remoteGroupFromJsonNode(String groupType, JsonNode node) {
        RemoteGroup group = new RemoteGroup();
        group.setId(groupType + node.get("uid").asText());
        group.setName(node.get("name").asText());
        return group;
    }

    public String getRedirectUrl() {
        if (authType.equals(AuthorizationType.AUTHORIZATION_CODE)) {
            return rolodexProperties.getUserAuthCredentials().getRedirectUri();
        } else if (authType.equals(AuthorizationType.CLIENT_CREDENTIALS)) {
            return rolodexProperties.getAppAuthCredentials().getRedirectUri();
        } else {
            // Actually will never happen, authType is checked on constructor
            return null;
        }
    }

    public void redirectToLogin(HttpServletResponse response) {
        String redirectUrl = rolodexProperties.getEndpoints().getLogoutEndpointUri();
        String redirectParams = "?response_type=code&client_id=" +
                rolodexProperties.getUserAuthCredentials().getClientId() + "&redirect_uri=" +
                rolodexProperties.getUserAuthCredentials().getRedirectUri() + "&scope=" +
                rolodexProperties.getUserAuthCredentials().getScope();
        try {
            response.sendRedirect(redirectUrl + redirectParams);
        } catch (IOException e1) {
            throw new RuntimeException("Error when redirecting to rolodex.");
        }
    }

    public String getOauth2TokenFromAuthCode(HttpServletRequest request) throws IOException {
        return getAuthorizationCodeToken(request.getParameter("code")).getToken();
    }

    private static class OAuth2Token {

        private static final long EXPIRATION_SECURITY_GAP_SECONDS = 10;

        private String token;

        private String type;

        private Instant expiresAt;

        private OAuth2Token(String token, String type) {
            this.token = token;
            this.type = type;
        }

        private OAuth2Token(String token, String type, Instant expiresAt) {
            this.token = token;
            this.type = type;
            this.expiresAt = expiresAt;
        }

        static OAuth2Token fromJsonNode(JsonNode node) {
            final String token = node.get("access_token").asText();
            final String type = node.get("token_type").asText();
            final Long expiresIn = node.get("expires_in").asLong();
            final Instant expiresAt = Instant.now().plus(expiresIn, ChronoUnit.SECONDS)
                    .minus(EXPIRATION_SECURITY_GAP_SECONDS, ChronoUnit.SECONDS);
            return new OAuth2Token(token, type, expiresAt);
        }

        public String getToken() {
            return token;
        }

        public String getType() {
            return type;
        }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    public static class AuthorizationType {
        public static final String CLIENT_CREDENTIALS = "client_credentials";

        public static final String AUTHORIZATION_CODE = "authorization_code";

        public static boolean validAuthType(String authType) {
            return authType.equals(CLIENT_CREDENTIALS) || authType.equals(AUTHORIZATION_CODE);
        }
    }

}
