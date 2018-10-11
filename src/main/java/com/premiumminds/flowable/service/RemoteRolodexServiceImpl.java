package com.premiumminds.flowable.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.premiumminds.flowable.conf.RolodexProperties;
import com.premiumminds.flowable.service.RolodexApi.AuthorizationType;
import com.premiumminds.flowable.utils.EmptyCacheException;
import com.premiumminds.flowable.utils.ExpiredCacheException;
import com.premiumminds.flowable.utils.SingleElementCache;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.security.DefaultPrivileges;
import org.flowable.ui.common.service.exception.NotFoundException;
import org.flowable.ui.common.service.exception.UnauthorizedException;
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

    private SingleElementCache<String, RemoteUser> usersCache;

    private SingleElementCache<String, RemoteGroup> groupsCache;

    protected String adminUser;

    protected String adminPassword;

    public RemoteRolodexServiceImpl(FlowableCommonAppProperties properties,
            RolodexProperties rolodexProperties) {
        rolodex = new RolodexApi(rolodexProperties, AuthorizationType.CLIENT_CREDENTIALS);
        initUsersCache();
        initGroupsCache();
        adminUser = properties.getIdmAdmin().getUser();
        adminPassword = properties.getIdmAdmin().getPassword();
    }

    private void initUsersCache() {
        usersCache = new SingleElementCache<>();
        populateUsersCache();
    }

    private void initGroupsCache() {
        groupsCache = new SingleElementCache<>();
        populateGroupsCache();
    }

    @Override
    public RemoteUser authenticateUser(String username, String password) {
        // TODO static or change to rolodex?
        if (username.equals(adminUser) && password.equals(adminPassword)) {
            RemoteUser admin = new RemoteUser();
            admin.setEmail("admin@premium-flow.com");
            admin.setFirstName("PremiumFlow");
            admin.setLastName("Admin");
            admin.setFullName("PremiumFlow Admin");
            admin.setId("bc4c66cc-d7b9-41b6-9559-fb4344d26f47");
            admin.getPrivileges().add(DefaultPrivileges.ACCESS_REST_API);
            admin.getPrivileges().add(DefaultPrivileges.ACCESS_TASK);
            admin.getPrivileges().add(DefaultPrivileges.ACCESS_ADMIN);

            return admin;
        } else {
            throw new UnauthorizedException("User not authorized!");
        }
    }

    @Override
    public RemoteToken getToken(String tokenValue) {
        // TODO
        LOGGER.info("TODO: getToken() Note: Change to get a token from a code?");
        RemoteToken token = new RemoteToken();
        token.setId("REMOTE_TOKEN_ID");
        token.setUserId("REMOTE_TOKEN_USER_ID");
        token.setValue(tokenValue);
        return token;
    }

    @Override
    public RemoteUser getUser(String userId) {
        List<RemoteUser> users;
        try {
            return usersCache.getElement(userId);
        } catch (NotFoundException | EmptyCacheException | ExpiredCacheException e) {
            users = populateUsersCache();
        }

        for (RemoteUser user : users) {
            if (user.getId().equals(userId)) {
                return user;
            }
        }
        throw new NotFoundException("User with id '" + userId + "' not found.");
    }

    @Override
    public List<RemoteUser> findUsersByNameFilter(String filter) {
        List<RemoteUser> users;
        try {
            users = new ArrayList<>(usersCache.getAll());
        } catch (ExpiredCacheException e) {
            users = populateUsersCache();
        } catch (EmptyCacheException e) {
            users = populateUsersCache();
        }
        if (filter == null || filter.equals("")) {
            return users;
        } else {
            return filterUsersByName(users, filter);
        }
    }

    @Override
    public List<RemoteUser> findUsersByGroup(String groupId) {

        List<RemoteUser> users;
        List<RemoteUser> candidateUsers = new ArrayList<>();

        // Verify that group exists
        if (!groupsCache.hasElement(groupId)) {
            throw new NotFoundException("No group with id '" + groupId + "' was found.");
        }

        try {
            users = new ArrayList<>(usersCache.getAll());
        } catch (ExpiredCacheException e) {
            users = populateUsersCache();
        } catch (EmptyCacheException e) {
            users = populateUsersCache();
        }

        for (RemoteUser user : users) {
            for (RemoteGroup group : user.getGroups()) {
                if (group.getId().equals(groupId)) {
                    candidateUsers.add(user);
                    break; // stop looping on user's groups
                }
            }
        }
        // possible to return empty list, group might not have any users
        return candidateUsers;
    }

    @Override
    public RemoteGroup getGroup(String groupId) {

        List<RemoteGroup> groups;
        try {
            return groupsCache.getElement(groupId);
        } catch (ExpiredCacheException e) {
            groups = populateGroupsCache();
        } catch (EmptyCacheException e) {
            groups = populateGroupsCache();
        } catch (NotFoundException e) {
            groups = populateGroupsCache();
        }
        // TODO: Handle composite (W:R) ids
        // TODO: remove W or R in start of id || check if composite id
        for (RemoteGroup group : groups) {
            if (group.getId().equals(groupId)) {
                return group;
            }
        }

        // No group with id found
        throw new NotFoundException("Group with id '" + groupId + "' not found.");
    }

    @Override
    public List<RemoteGroup> findGroupsByNameFilter(String filter) {
        List<RemoteGroup> groups;

        try {
            groups = new ArrayList<>(groupsCache.getAll());
        } catch (ExpiredCacheException e) {
            groups = populateGroupsCache();
        } catch (EmptyCacheException e) {
            groups = populateGroupsCache();
        }

        if (filter == null || filter.equals("")) {
            return groups;
        } else {
            return filterGroupsByName(groups, filter);
        }
    }

    protected List<RemoteUser> populateUsersCache() {
        try {
            List<RemoteUser> users = rolodex.getEmployees();
            for (RemoteUser user : users) {
                usersCache.addElement(user.getId(), user);
            }
            usersCache.updateExpirationTime();
            return users;
        } catch (IOException e) {
            LOGGER.error("Failed to load users from rolodex.", e);
            throw new RuntimeException("Failed to load users from rolodex.", e);
        }
    }

    protected List<RemoteGroup> populateGroupsCache() {
        try {
            List<RemoteGroup> groups = rolodex.getGroups();
            for (RemoteGroup group : groups) {
                groupsCache.addElement(group.getId(), group);
            }
            groupsCache.updateExpirationTime();
            return groups;
        } catch (IOException e) {
            LOGGER.error("Failed to load groups from rolodex.", e);
            throw new RuntimeException("Failed to load groups from rolodex.", e);
        }
    }

    protected List<RemoteUser> filterUsersByName(List<RemoteUser> users, String nameFilter) {
        List<RemoteUser> matchingUsers = new ArrayList<>();

        for (RemoteUser user : users) {
            if (user.getFullName().toLowerCase().contains(nameFilter.toLowerCase())) {
                matchingUsers.add(user);
            }
        }
        return matchingUsers;
    }

    protected List<RemoteGroup> filterGroupsByName(List<RemoteGroup> groups, String nameFilter) {
        List<RemoteGroup> matchingGroups = new ArrayList<>();

        for (RemoteGroup group : groups) {
            if (group.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                matchingGroups.add(group);
            }
        }
        return matchingGroups;
    }
}
