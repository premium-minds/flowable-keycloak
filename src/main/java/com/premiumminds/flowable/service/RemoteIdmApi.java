package com.premiumminds.flowable.service;

import java.util.List;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteUser;

public interface RemoteIdmApi {
    List<RemoteUser> getUsers();

    List<RemoteGroup> getGroups();
}
