package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
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

    private RolodexApi rolodex;

    private LoadingCache<String, List<RemoteUser>> usersCache;

    // private LoadingCache<String, RemoteGroup> groupsCache;

    public RemoteRolodexServiceImpl(FlowableCommonAppProperties properties) {
        url = properties.determineIdmAppUrl();
        adminUser = properties.getIdmAdmin().getUser();
        Assert.hasText(adminUser, "Admin user must not be empty");
        adminPassword = properties.getIdmAdmin().getPassword();
        Assert.hasText(adminUser, "Admin user password should not be empty");
        rolodex = new RolodexApi();
        initUsersCache();
    }

    private void initUsersCache() {
        usersCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, List<RemoteUser>>() {
                    @Override
                    public List<RemoteUser> load(String userId) throws Exception {
                        LOGGER.info("load() invoked");
                        return rolodex.getEmployees();
                    }
                });
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
        List<RemoteUser> matchingEmployees = new ArrayList<>();

        try {
            employees = usersCache.get("");
            LOGGER.info("Users cache size: " + employees.size());
            if (filter == null || filter == "") {
                return employees;
            }

            for (RemoteUser user : employees) {
                if (user.getFullName().toLowerCase().contains(filter.toLowerCase())) {
                    matchingEmployees.add(user);
                }
            }
            return matchingEmployees;

        } catch (ExecutionException e1) {
            LOGGER.error("Failed to load users from cache");
            // TOOD: Get them from rolodex!!!!!
            e1.printStackTrace();
        }
        return matchingEmployees;

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
        List<RemoteGroup> groups;
        List<RemoteGroup> matchingResults;

        try {
            groups = rolodex.getGroups();
            // no filter applied, return all groups
            if (filter == null || filter == "") {
                return groups;
            }

            matchingResults = new ArrayList<>();
            for (RemoteGroup group : groups) {
                if (group.getName().toLowerCase().contains(filter.toLowerCase())) {
                    matchingResults.add(group);
                }
            }
            return matchingResults;
        } catch (IOException e) {
            LOGGER.error("Unable to retrieve groups.");
            return new ArrayList<>(0);
        }
    }
}
