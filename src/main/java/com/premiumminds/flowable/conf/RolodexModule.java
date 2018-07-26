package com.premiumminds.flowable.conf;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

public class RolodexModule {

    private String appName;

    private Config conf = ConfigFactory.load();

    public RolodexModule() {
        this.appName = conf.getString("application.name");
    }

    public String getAppName() {
        return appName;
    }

}
