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
package com.premiumminds.flowable.filter;

import com.premiumminds.flowable.conf.KeycloakProperties;
import java.util.Collection;
import javax.annotation.PostConstruct;
import org.flowable.ui.common.filter.FlowableCookieFilterCallback;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

public class KeycloakCookieFilterRegistrationBean extends FilterRegistrationBean {

    protected final RemoteIdmService remoteIdmService;

    protected final FlowableCommonAppProperties properties;

    protected final KeycloakProperties keycloakProperties;

    protected FlowableCookieFilterCallback filterCallback;

    protected Collection<String> requiredPrivileges;

    public KeycloakCookieFilterRegistrationBean(RemoteIdmService remoteIdmService,
            FlowableCommonAppProperties properties, KeycloakProperties keycloakProperties) {
        this.remoteIdmService = remoteIdmService;
        this.properties = properties;
        this.keycloakProperties = keycloakProperties;
    }

    @PostConstruct
    protected void initializeFilter() {
        if (getFilter() == null) {
            KeycloakCookieFilter keycloakCookieFilter =
                    new KeycloakCookieFilter(remoteIdmService, properties, keycloakProperties);

            keycloakCookieFilter.setFilterCallback(filterCallback);
            keycloakCookieFilter.setRequiredPrivileges(requiredPrivileges);
            setFilter(keycloakCookieFilter);
        }
    }

    @Autowired(required = false)
    public void setFilterCallback(FlowableCookieFilterCallback filterCallback) {
        this.filterCallback = filterCallback;
    }

    public void setRequiredPrivileges(Collection<String> requiredPrivileges) {
        this.requiredPrivileges = requiredPrivileges;
    }

}
