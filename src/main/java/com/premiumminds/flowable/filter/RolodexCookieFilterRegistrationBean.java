package com.premiumminds.flowable.filter;

import javax.annotation.PostConstruct;
import org.flowable.ui.common.filter.FlowableCookieFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

public class RolodexCookieFilterRegistrationBean extends FilterRegistrationBean {

    @PostConstruct
    protected void initializeFilter() {
        if (getFilter() == null) {
            RolodexCookieFilter rolodexCookieFilter = new RolodexCookieFilter();
            setFilter(rolodexCookieFilter);
        }
    }

}
