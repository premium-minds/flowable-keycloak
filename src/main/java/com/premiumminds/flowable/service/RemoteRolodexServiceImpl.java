package com.premiumminds.flowable.service;

import java.util.List;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

@Primary
@Service
public class RemoteRolodexServiceImpl implements RemoteIdmService {
    public RemoteUser authenticateUser(String username, String password) {
        return null;
    }

    public RemoteToken getToken(String tokenValue) {
        return null;
    }

    public RemoteUser getUser(String userId) {
        return null;
    }

    public List<RemoteUser> findUsersByNameFilter(String filter) {
        return null;
    }

    public List<RemoteUser> findUsersByGroup(String groupId) {
        return null;
    }

    public RemoteGroup getGroup(String groupId) {
        return null;
    }

    public List<RemoteGroup> findGroupsByNameFilter(String filter) {
        return null;
    }
}
