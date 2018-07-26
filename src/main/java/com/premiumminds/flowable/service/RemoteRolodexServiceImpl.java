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
        usersCache = CacheBuilder.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, List<RemoteUser>>() {
                    @Override
                    public List<RemoteUser> load(String userId) throws Exception {
                        LOGGER.info("load() invoked");
                        return getEmployeesByFilter(userId);
                    }
                });
    }

    private List<RemoteUser> getEmployeesByFilter(String userId)
            throws IOException, ExecutionException {
        if (userId == "") {
            // Load all from database
            LOGGER.info("Loading all users from rolodex");
            return rolodex.getEmployees();
        } else {
            // Apply filter to the list
            LOGGER.info("Using filter '" + userId + "' to select some users.");
            List<RemoteUser> matchingEmployees = new ArrayList<>();
            List<RemoteUser> employees = usersCache.get("");

            for (RemoteUser user : employees) {
                if (user.getFullName().toLowerCase().contains(userId.toLowerCase())) {
                    matchingEmployees.add(user);
                }
            }
            return matchingEmployees;
        }
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

        try {
            return usersCache.get(filter.toLowerCase());

        } catch (ExecutionException e1) {
            LOGGER.error("Failed to load users from cache. Loading directly from rolodex.");
            try {
                return rolodex.getEmployees();
            } catch (IOException e) {
                LOGGER.error("Users could not be loaded from rolodex.");
            }
        }
        return new ArrayList<>();
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
