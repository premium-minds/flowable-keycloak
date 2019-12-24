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
