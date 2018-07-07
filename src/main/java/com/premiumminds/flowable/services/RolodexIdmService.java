package com.premiumminds.flowable.services;

import java.util.List;
import org.flowable.ui.common.model.RemoteGroup;
import org.flowable.ui.common.model.RemoteToken;
import org.flowable.ui.common.model.RemoteUser;
import org.flowable.ui.common.service.idm.RemoteIdmService;

public class RolodexIdmService implements RemoteIdmService {
    public RemoteUser authenticateUser(String username, String password) {
        if("admin".equals(username)){
            RemoteUser user = new RemoteUser();
            user.setId("ADMIN_ID");
            user.setFirstName("Senhor");
            user.setLastName("Admin");
            user.setFullName("Senhor António Admin");
            user.setEmail("acamilo@pminds.pt");
            user.getGroups().add(new RemoteGroup("GROUP1_ID", "Group 1"));
            user.getPrivileges().add("ROLE_ADMIN");
            return user;
        }
        return null;
    }

    public RemoteToken getToken(String tokenValue) {
        System.out.println("Called getToken("+tokenValue+")");
        RemoteToken token = new RemoteToken();
        token.setId("TOKEN_ID");
        token.setValue("TOKEN_VALUE");
        token.setUserId("ADMIN_ID");
        return token;
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
