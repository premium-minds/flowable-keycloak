package com.premiumminds.flowable.filter;

import java.util.Collection;
import javax.annotation.PostConstruct;
import org.flowable.ui.common.filter.FlowableCookieFilterCallback;
import org.flowable.ui.common.properties.FlowableCommonAppProperties;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

public class RolodexCookieFilterRegistrationBean extends FilterRegistrationBean {

    protected final RemoteIdmService remoteIdmService;

    protected final FlowableCommonAppProperties properties;

    protected FlowableCookieFilterCallback filterCallback;

    protected Collection<String> requiredPrivileges;

    public RolodexCookieFilterRegistrationBean(RemoteIdmService remoteIdmService,
            FlowableCommonAppProperties properties) {
        this.remoteIdmService = remoteIdmService;
        this.properties = properties;
    }

    @PostConstruct
    protected void initializeFilter() {
        if (getFilter() == null) {
            RolodexCookieFilter rolodexCookieFilter =
                    new RolodexCookieFilter(remoteIdmService, properties);

            rolodexCookieFilter.setFilterCallback(filterCallback);
            rolodexCookieFilter.setRequiredPrivileges(requiredPrivileges);
            rolodexCookieFilter.initCaches();
            setFilter(rolodexCookieFilter);
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
