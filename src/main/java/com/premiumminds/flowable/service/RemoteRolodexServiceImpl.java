package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.premiumminds.flowable.rolodex.RolodexApi;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.security.DefaultPrivileges;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

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

    @Override
    public RemoteUser authenticateUser(String username, String password) {
        RemoteUser user = new RemoteUser();
        user.setId("jcoelho");
        user.setFirstName("José");
        user.setLastName("Coelho");
        user.setEmail("jose.coelho@premium-minds.com");
        user.setTenantId("TENANT ID");
        user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user.getPrivileges().add(DefaultPrivileges.ACCESS_REST_API);
        user.getPrivileges().add(DefaultPrivileges.ACCESS_TASK);
        user.getPrivileges().add(DefaultPrivileges.ACCESS_ADMIN);

        return user;
    }

    @Override
    public RemoteToken getToken(String tokenValue) {
        return null;
    }

    @Override
    public RemoteUser getUser(String userId) {
        RemoteUser user = new RemoteUser();
        user.setId("jcoelho");
        user.setFirstName("José");
        user.setLastName("Coelho");
        user.setEmail("jose.coelho@premium-minds.com");
        user.setTenantId("TENANT ID");
        user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user.getPrivileges().add("Privilege 1");
        return user;
    }

    @Override
    public List<RemoteUser> findUsersByNameFilter(String filter) {

        List<RemoteUser> employees;
        List<RemoteUser> foundEmployees;

        RolodexApi rolodex = new RolodexApi();
        try {
            RolodexApi.OAuth2Token token = rolodex.getClientCredentialsToken();
            employees = rolodex.getEmployees(token);
            foundEmployees = new ArrayList<>();

            for (RemoteUser user : employees) {
                if (user.getFullName().toLowerCase().contains(filter.toLowerCase())) {
                    foundEmployees.add(user);
                }
            }
            return foundEmployees;
        } catch (IOException e) {
            LOGGER.error("Unable to retrieve users.");
            return new ArrayList<>(0);
        }
    }

    @Override
    public List<RemoteUser> findUsersByGroup(String groupId) {
        return null;
    }

    @Override
    public RemoteGroup getGroup(String groupId) {
        return null;
    }

    @Override
    public List<RemoteGroup> findGroupsByNameFilter(String filter) {
        return null;
    }
}
