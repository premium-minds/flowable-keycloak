package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.ObjectMapper;
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
    	System.out.println("AUTHENTICATE USER");
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
        RemoteUser user1 = new RemoteUser();
        user1.setId("jcoelho");
        user1.setFirstName("José");
        user1.setLastName("Coelho");
        user1.setEmail("jose.coelho@premium-minds.com");
        user1.setTenantId("TENANT ID");
        user1.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user1.getPrivileges().add("Privilege 1");

        RemoteUser user2 = new RemoteUser();
        user2.setId("respadinha");
        user2.setFirstName("Ricardo");
        user2.setLastName("Espadinha");
        user2.setEmail("ricardo.espadinha@premium-minds.com");
        user2.setTenantId("TENANT ID RE");
        user2.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user2.getPrivileges().add("Privilege 1");

        List<RemoteUser> list = new ArrayList<>();
        list.add(user1);
        list.add(user2);
        return list;

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
