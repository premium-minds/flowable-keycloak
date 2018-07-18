package com.premiumminds.flowable.rolodex;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RolodexApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(RolodexApi.class);

    private static final String PROVIDER_URL = "http://ci.rolodex.forno.premium-minds.com/api/";

    private static final String TOKEN_ENDPOINT = "oauth2/token";

    private static final String EMPLOYEES_ENDPOINT = "employees";

    private static final String GROUPS_ENDPOINT = "workgroups";

    private static final String ROLES_ENDPOINT = "workgroups/roles";

    private static final String CLIENT_ID = "e9bcb917-2bd2-412e-b131-ef33039cdf5a";

    private static final String CLIENT_SECRET = "r1xQ3/a$UD4yhqzAH[";

    private static final String SCOPES = "rolodex.employees/read rolodex.workgroups/read";

    private static final String REDIRECT_URI =
            "http://localhost:8080/ui/callback?client_name=RolodexClient";

    private final Config config;

    private final ObjectMapper mapper;

    public RolodexApi() {

        final URI tokenEndpointURI = URI.create(PROVIDER_URL + TOKEN_ENDPOINT);
        final URI employeesEndpointURI = URI.create(PROVIDER_URL + EMPLOYEES_ENDPOINT);
        final URI groupsEndpointURI = URI.create(PROVIDER_URL + GROUPS_ENDPOINT);
        final URI rolesEndpointURI = URI.create(PROVIDER_URL + ROLES_ENDPOINT);
        final URI redirectUri = URI.create(REDIRECT_URI);

        this.config = new Config(tokenEndpointURI, employeesEndpointURI, groupsEndpointURI,
                rolesEndpointURI, CLIENT_ID, CLIENT_SECRET, SCOPES, redirectUri);

        this.mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public OAuth2Token getClientCredentialsToken() throws IOException {

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

            post.setEntity(
                    new UrlEncodedFormEntity(generateClientCredentialsRequestParams(config)));

            generateClientCredentialsRequestHeaders(post);

            LOGGER.info(post.toString());
            for (Header h : post.getAllHeaders()) {
                LOGGER.info("HEADER: " + h.getName() + " - " + h.getValue());
            }
            LOGGER.info(post.getEntity().toString());

            return post;
        } catch (UnsupportedEncodingException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private List<NameValuePair> generateClientCredentialsRequestParams(Config config) {
        List<NameValuePair> rparams = new ArrayList<>(3);
        rparams.add(new BasicNameValuePair("grant_type", "client_credentials"));
        rparams.add(new BasicNameValuePair("scope", config.getScope()));
        rparams.add(new BasicNameValuePair("redirect_uri", config.getRedirectURI().toString()));
        return rparams;
    }

    private void generateClientCredentialsRequestHeaders(HttpPost post) {

        post.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + new String(Base64.getEncoder()
                .encode((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(Charset.forName("UTF-8")))));
        post.addHeader(HttpHeaders.CONTENT_TYPE,
                ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        post.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    public static class OAuth2Token {

        private final String token;

        private OAuth2Token(String token) {
            this.token = token;
        }

        static OAuth2Token fromJsonNode(JsonNode node) {
            final String token = node.get("access_token").asText();
            return new OAuth2Token(token);
        }

        public String getToken() {
            return token;
        }
    }

    public static class Config {

        private final URI tokenEndpointURI;

        private final URI usersEndpointURI;

        private final URI groupsEndpointURI;

        private final URI rolesEndpointURI;

        private final String clientId;

        private final String clientSecret;

        private final String scope;

        private final URI redirectURI;

        public Config(URI tokenEndpointURI, URI usersEndpointURI, URI groupsEndpointURI,
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
