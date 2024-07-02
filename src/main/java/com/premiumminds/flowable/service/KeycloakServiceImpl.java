/**
 * Copyright (C) 2020 Premium Minds.
 *
 * This file is part of Flowable Keycloak.
 *
 * Flowable Keycloak is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Flowable Keycloak is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Flowable Keycloak. If not, see <http://www.gnu.org/licenses/>.
 */
package com.premiumminds.flowable.service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.premiumminds.flowable.conf.KeycloakProperties;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.ws.rs.NotFoundException;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.service.exception.UnauthorizedException;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

@Primary
@Service
public class KeycloakServiceImpl implements RemoteIdmService {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakServiceImpl.class);

    private final RealmResource realm;

    private final OIDCClient oidcClient;

    private final KeycloakAccessTokenExtractor accessTokenExtractor;

    private final LoadingCache<String, Optional<RemoteUser>> usersCache;

    private final LoadingCache<String, Optional<RemoteGroup>> groupsCache;

    private final LoadingCache<String, List<RemoteUser>> groupsUsersCache;

    public KeycloakServiceImpl(KeycloakProperties keycloakProperties) {
        ResteasyClientBuilder clientBuilder = new ResteasyClientBuilder();
        clientBuilder.register(new KeycloakClientJacksonProvider(), 100);
        ResteasyClient client = clientBuilder.build();

        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getUrl())
                .realm(keycloakProperties.getRealm())
                .clientId(keycloakProperties.getClient().getClientId())
                .clientSecret(keycloakProperties.getClient().getClientSecret())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .resteasyClient(client)
                .build();

        this.realm = keycloak.realm(keycloakProperties.getRealm());

        OIDCMetadataHolder metadataHolder = new OIDCMetadataHolder(keycloakProperties);
        this.oidcClient = new OIDCClient(keycloakProperties, metadataHolder);
        this.accessTokenExtractor = new KeycloakAccessTokenExtractor(keycloakProperties, metadataHolder);

        this.usersCache = CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(30, TimeUnit.MINUTES)
                .weakValues()
                .build(new CacheLoader<String, Optional<RemoteUser>>() {
                    @Override
                    public Optional<RemoteUser> load(String userId) {
                        try {
                            final UserRepresentation user = realm.users().get(userId).toRepresentation();
                            final List<GroupRepresentation> groups = realm.users().get(userId).groups();

                            return Optional.of(convertUser(user, groups));
                        } catch (NotFoundException ex) {
                            return Optional.empty();
                        }
                    }
                });

        this.groupsCache = CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(30, TimeUnit.MINUTES)
                .weakValues()
                .build(new CacheLoader<String, Optional<RemoteGroup>>() {
                    @Override
                    public Optional<RemoteGroup> load(String groupId) {
                        try {
                            return Optional.of(convertGroup(realm.groups().group(groupId).toRepresentation()));
                        } catch (NotFoundException ex) {
                            return Optional.empty();
                        }
                    }
                });

        this.groupsUsersCache = CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterWrite(30, TimeUnit.MINUTES)
                .weakValues()
                .build(new CacheLoader<String, List<RemoteUser>>() {
                    @Override
                    public List<RemoteUser> load(String groupId) {
                        return realm.groups().group(groupId).members().stream()
                                .map(KeycloakServiceImpl.this::convertUser).collect(Collectors.toList());
                    }
                });
    }

    @Override
    public RemoteUser authenticateUser(String username, String password) {
        try {
            OIDCTokens tokens = oidcClient.authenticate(username, password);
            String accessToken = tokens.getBearerAccessToken().getValue();
            List<String> roles = accessTokenExtractor.getRoles(accessToken);

            RemoteUser user = new RemoteUser();
            user.setId(username);
            user.getPrivileges().addAll(roles);
            return user;
        } catch (Exception e) {
            LOGGER.warn("error authenticating", e);
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
        try {
            return usersCache.get(userId)
                    .orElseThrow(() -> new NotFoundException("user with id '" + userId + "' not found"));
        } catch (ExecutionException e) {
            throw new RuntimeException("error getting user", e);
        }
    }

    @Override
    public List<RemoteUser> findUsersByNameFilter(String filter) {
        return realm.users().search(filter, 0, 20).stream()
                .map(this::convertUser)
                .collect(Collectors.toList());
    }

    @Override
    public List<RemoteUser> findUsersByGroup(String groupId) {
        try {
            return groupsUsersCache.get(groupId);
        } catch (ExecutionException e) {
            throw new RuntimeException("error getting users of group '" + groupId + "'", e);
        }
    }

    @Override
    public RemoteGroup getGroup(String groupId) {
        try {
            return groupsCache.get(groupId)
                    .orElseThrow(() -> new NotFoundException("group with id '" + groupId + "' not found"));
        } catch (ExecutionException ex) {
            throw new RuntimeException("error getting group", ex);
        }
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
