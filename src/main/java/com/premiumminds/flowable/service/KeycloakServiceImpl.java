package com.premiumminds.flowable.service;

import com.premiumminds.flowable.conf.KeycloakProperties;
import java.util.List;
import java.util.stream.Collectors;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.security.DefaultPrivileges;
import org.flowable.ui.common.service.exception.UnauthorizedException;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

@Primary
@Service
public class KeycloakServiceImpl implements RemoteIdmApi, RemoteIdmService {
    private final Keycloak keycloak;

    private final RealmResource realm;

    private final String adminUsername;

    private final String adminPassword;

    public KeycloakServiceImpl(KeycloakProperties keycloakProperties) {
        this.keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getUrl())
                .realm(keycloakProperties.getRealm())
                .clientId(keycloakProperties.getClient().getClientId())
                .clientSecret(keycloakProperties.getClient().getClientSecret())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();

        this.realm = keycloak.realm(keycloakProperties.getRealm());

        this.adminUsername = keycloakProperties.getAdminUsername();
        this.adminPassword = keycloakProperties.getAdminPassword();
    }

    @Override
    public List<RemoteUser> getUsers() {
        return realm.users().list(0, 200).stream().map(this::convertUser)
                .collect(Collectors.toList());
    }

    @Override
    public List<RemoteGroup> getGroups() {
        return realm.groups().groups(0, 200).stream().map(this::convertGroup)
                .collect(Collectors.toList());
    }

    @Override
    public RemoteUser authenticateUser(String username, String password) {
        if (username != null && password != null && username.equals(adminUsername) && password.equals(adminPassword)) {
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
            throw new UnauthorizedException("call authenticateUser(username='" + username +
                    "') username or password no recognized");
        }
    }

    @Override
    public RemoteToken getToken(String tokenValue) {
        throw new IllegalStateException("method should not be called");
    }

    @Override
    public RemoteUser getUser(String userId) {
        final UserRepresentation user = realm.users().get(userId).toRepresentation();
        final List<GroupRepresentation> groups = realm.users().get(userId).groups();

        return convertUser(user, groups);
    }

    @Override
    public List<RemoteUser> findUsersByNameFilter(String filter) {
        return realm.users().search(filter, 0, 20).stream()
                .map(this::convertUser)
                .collect(Collectors.toList());
    }

    @Override
    public List<RemoteUser> findUsersByGroup(String groupId) {
        return realm.groups().group(groupId).members().stream().map(this::convertUser).collect(Collectors.toList());
    }

    @Override
    public RemoteGroup getGroup(String groupId) {
        return convertGroup(realm.groups().group(groupId).toRepresentation());
    }

    @Override
    public List<RemoteGroup> findGroupsByNameFilter(String filter) {
        return realm.groups().groups(filter, 0, 20).stream().map(this::convertGroup)
                .collect(Collectors.toList());
    }

    private RemoteUser convertUser(UserRepresentation user) {
        RemoteUser remoteUser = new RemoteUser();
        remoteUser.setId(user.getId());
        remoteUser.setFullName(user.getFirstName() + " " + user.getLastName());
        remoteUser.setFirstName(user.getFirstName());
        remoteUser.setLastName(user.getLastName());
        remoteUser.setEmail(user.getEmail());
        return remoteUser;
    }

    private RemoteGroup convertGroup(GroupRepresentation group) {
        RemoteGroup remoteGroup = new RemoteGroup();
        remoteGroup.setId(group.getId());
        remoteGroup.setName(group.getName());
        return remoteGroup;
    }

    private RemoteUser convertUser(UserRepresentation user, List<GroupRepresentation> groups) {
        RemoteUser remoteUser = convertUser(user);
        remoteUser.setGroups(groups.stream().map(this::convertGroup).collect(Collectors.toList()));
        return remoteUser;
    }

}
