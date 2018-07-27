package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

@Primary
@Service
public class RemoteRolodexServiceImpl implements RemoteIdmService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteRolodexServiceImpl.class);

    @Autowired
    protected ObjectMapper objectMapper;

    private RolodexApi rolodex;

    private LoadingCache<String, List<RemoteUser>> usersCache;

    private LoadingCache<String, List<RemoteGroup>> groupsCache;

    public RemoteRolodexServiceImpl(FlowableCommonAppProperties properties) {
        rolodex = new RolodexApi();
        initUsersCache();
        initGroupsCache();
    }

    private void initUsersCache() {
        usersCache = CacheBuilder.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, List<RemoteUser>>() {
                    @Override
                    public List<RemoteUser> load(String userName) throws Exception {
                        return getEmployeesByFilter(userName);
                    }
                });
    }

    private void initGroupsCache() {
        groupsCache = CacheBuilder.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).recordStats()
                .build(new CacheLoader<String, List<RemoteGroup>>() {

                    @Override
                    public List<RemoteGroup> load(String groupName) throws Exception {
                        return getGroupsByFilter(groupName);
                    }

                });
    }

    private List<RemoteUser> getEmployeesByFilter(String userName)
            throws IOException, ExecutionException {
        if (userName == "") {
            // Load all from database
            return rolodex.getEmployees();
        } else {
            // Apply filter to the list
            List<RemoteUser> matchingEmployees = new ArrayList<>();
            List<RemoteUser> employees = usersCache.get("");

            for (RemoteUser user : employees) {
                if (user.getFullName().toLowerCase().contains(userName.toLowerCase())) {
                    matchingEmployees.add(user);
                }
            }
            return matchingEmployees;
        }
    }

    private List<RemoteGroup> getGroupsByFilter(String groupName)
            throws IOException, ExecutionException {
        if (groupName == "") {
            // Load all from database
            return rolodex.getGroups();
        } else {
            // Apply filter to the list
            List<RemoteGroup> matchingGroups = new ArrayList<>();
            List<RemoteGroup> groups = groupsCache.get("");

            for (RemoteGroup group : groups) {
                if (group.getName().toLowerCase().contains(groupName.toLowerCase())) {
                    matchingGroups.add(group);
                }
            }
            return matchingGroups;
        }
    }

    @Override
    public RemoteUser authenticateUser(String username, String password) {
        RemoteUser user = new RemoteUser();
        user.setId("jcoelho");
        user.setFirstName("José");
        user.setLastName("Coelho");
        user.setEmail("jose.coelho@premium-minds.com");
        user.setTenantId("");
        user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user.getPrivileges().add(DefaultPrivileges.ACCESS_REST_API);
        user.getPrivileges().add(DefaultPrivileges.ACCESS_TASK);
        user.getPrivileges().add(DefaultPrivileges.ACCESS_ADMIN);

        return user;
    }

    @Override
    public RemoteToken getToken(String tokenValue) {
        RemoteToken token = new RemoteToken();
        token.setId("REMOTE_TOKEN_ID");
        token.setUserId("REMOTE_TOKEN_USER_ID");
        token.setValue(tokenValue);
        return token;
    }

    @Override
    public RemoteUser getUser(String userId) {
        RemoteUser user = new RemoteUser();
        user.setId("jcoelho");
        user.setFirstName("José");
        user.setLastName("Coelho");
        user.setEmail("jose.coelho@premium-minds.com");
        user.setTenantId("");
        user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1 Name"));
        user.getPrivileges().add("Privilege 1");
        return user;
    }

    @Override
    public List<RemoteUser> findUsersByNameFilter(String filter) {

        try {
            if (filter == null) {
                // avoid annoying bug from flowable when no filter is sent
                return usersCache.get("");
            }
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

        Map<String, RemoteGroup> groupsMap = new HashMap<>();
        try {
            List<RemoteGroup> groups = groupsCache.get("");
            for (RemoteGroup g : groups) {
                groupsMap.put(g.getId(), g);
            }
        } catch (ExecutionException e) {
            LOGGER.warn("Failed to load data from cache.");
            try {
                List<RemoteGroup> groups = rolodex.getGroups();
                for (RemoteGroup g : groups) {
                    groupsMap.put(g.getId(), g);
                }
            } catch (IOException e1) {
                LOGGER.error("Failed to load data from rolodex.");
            }
        }
        return groupsMap.get(groupId);
    }

    @Override
    public List<RemoteGroup> findGroupsByNameFilter(String filter) {

        try {
            if (filter == null) {
                // avoid annoying bug from flowable when no filter is sent
                return groupsCache.get("");
            }
            return groupsCache.get(filter.toLowerCase());

        } catch (ExecutionException e1) {
            LOGGER.error("Failed to load groups from cache. Loading directly from rolodex.");
            try {
                return rolodex.getGroups();
            } catch (IOException e) {
                LOGGER.error("Groups could not be loaded from rolodex.");
            }
        }
        return new ArrayList<>();
    }
}
