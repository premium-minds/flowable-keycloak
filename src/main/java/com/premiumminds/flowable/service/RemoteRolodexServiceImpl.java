package com.premiumminds.flowable.service;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.List;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Primary
@Service
public class RemoteRolodexServiceImpl implements RemoteIdmService {

	private static final Logger LOGGER = LoggerFactory.getLogger(RemoteRolodexServiceImpl.class);

    @Autowired
    protected ObjectMapper objectMapper;
	
    protected String url;
    protected String adminUser;
    protected String adminPassword;
    
    public RemoteRolodexServiceImpl(FlowableCommonAppProperties properties) {
        url = properties.determineIdmAppUrl();
        adminUser = properties.getIdmAdmin().getUser();
        Assert.hasText(adminUser, "Admin user must not be empty");
        adminPassword = properties.getIdmAdmin().getPassword();
        Assert.hasText(adminUser, "Admin user password should not be empty");
    }
    
    public RemoteUser authenticateUser(String username, String password) {
        return null;
    }

    public RemoteToken getToken(String tokenValue) {
        return null;
    }

    public RemoteUser getUser(String userId) {
        return null;
    }

    public List<RemoteUser> findUsersByNameFilter(String filter) {
        return null;
    }

    public List<RemoteUser> findUsersByGroup(String groupId) {
        return null;
    }

    public RemoteGroup getGroup(String groupId) {
        return null;
    }

    public List<RemoteGroup> findGroupsByNameFilter(String filter) {
        return null;
    }
}
