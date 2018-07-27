package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
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

    private final OAuth2Config config;

    private Optional<OAuth2Token> token;

    private final ObjectMapper mapper;

    public RolodexApi() {

        Config conf = ConfigFactory.load();
        String providerUrl = conf.getString("oauth2.provider.uri");

        final URI tokenEndpointURI = URI.create(providerUrl + conf.getString("endpoints.token"));
        final URI employeesEndpointURI =
                URI.create(providerUrl + conf.getString("endpoints.employees"));
        final URI groupsEndpointURI = URI.create(providerUrl + conf.getString("endpoints.groups"));
        final URI rolesEndpointURI = URI.create(providerUrl + conf.getString("endpoints.roles"));
        final URI redirectUri = URI.create(conf.getString("oauth2.provider.redirect_uri"));

        this.config = new OAuth2Config(tokenEndpointURI, employeesEndpointURI, groupsEndpointURI,
                rolesEndpointURI, conf.getString("oauth2.provider.client_id"),
                conf.getString("oauth2.provider.client_secret"),
                conf.getString("oauth2.provider.scopes"), redirectUri);

        this.mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        this.token = Optional.empty();

    }

    private OAuth2Token getOauth2Token() throws IOException {
        if (!token.isPresent() || token.get().isExpired()) {
            token = Optional.of(getClientCredentialsToken());
        }
        return token.get();
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
            URIBuilder uriBuilder = new URIBuilder(config.getTokenEndpointURI());
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
        rparams.add(new BasicNameValuePair("grant_type", "client_credentials"));
        rparams.add(new BasicNameValuePair("scope", config.getScope()));
        rparams.add(new BasicNameValuePair("redirect_uri", config.getRedirectURI().toString()));
        return rparams;
    }

    private void generateClientCredentialsRequestHeaders(HttpPost post) {
        post.addHeader(HttpHeaders.AUTHORIZATION,
                "Basic " + new String(Base64.getEncoder()
                        .encode((config.getClientId() + ":" + config.getClientSecret())
                                .getBytes(Charset.forName("UTF-8")))));
        post.addHeader(HttpHeaders.CONTENT_TYPE,
                ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        post.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    public List<RemoteUser> getEmployees() throws IOException {

        OAuth2Token token = getOauth2Token();
        Map<String, String> workgroups = new HashMap<>();
        Map<String, String> roles = new HashMap<>();

        HttpGet request = getGetRequest(config.getUsersEndpointURI(), token);
        CloseableHttpClient client = HttpClients.createDefault();
        List<RemoteUser> employees = new ArrayList<>();

        JsonNode workgroupsJson = getWorkgroups(token);
        JsonNode rolesJson = getRoles(token);

        for (JsonNode elem : workgroupsJson) {
            workgroups.put(elem.get("uid").asText(), elem.get("name").asText());
        }

        for (JsonNode elem : rolesJson) {
            roles.put(elem.get("uid").asText(), elem.get("name").asText());
        }

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

    public List<RemoteGroup> getGroups() throws IOException {

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
        HttpGet request = getGetRequest(config.getGroupsEndpointURI(), token);
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
        HttpGet request = getGetRequest(config.getRolesEndpointURI(), token);
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

    private HttpGet getGetRequest(URI uri, OAuth2Token token) {
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

    private static class OAuth2Token {

        private static final long EXPIRATION_SECURITY_GAP_SECONDS = 10;

        private final String token;

        private final String type;

        private final Instant expiresAt;

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

    public static class OAuth2Config {

        private final URI tokenEndpointURI;

        private final URI usersEndpointURI;

        private final URI groupsEndpointURI;

        private final URI rolesEndpointURI;

        private final String clientId;

        private final String clientSecret;

        private final String scope;

        private final URI redirectURI;

        public OAuth2Config(URI tokenEndpointURI, URI usersEndpointURI, URI groupsEndpointURI,
                URI rolesEndpointURI, String clientId, String clientSecret, String scope,
                URI redirectURI) {

            this.tokenEndpointURI = tokenEndpointURI;
            this.usersEndpointURI = usersEndpointURI;
            this.groupsEndpointURI = groupsEndpointURI;
            this.rolesEndpointURI = rolesEndpointURI;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.scope = scope;
            this.redirectURI = redirectURI;
        }

        public URI getTokenEndpointURI() {
            return tokenEndpointURI;
        }

        public URI getUsersEndpointURI() {
            return usersEndpointURI;
        }

        public URI getGroupsEndpointURI() {
            return groupsEndpointURI;
        }

        public URI getRolesEndpointURI() {
            return rolesEndpointURI;
        }

        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public String getScope() {
            return scope;
        }

        public URI getRedirectURI() {
            return redirectURI;
        }
    }
}
