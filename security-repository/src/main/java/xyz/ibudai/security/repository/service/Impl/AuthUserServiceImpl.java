package xyz.ibudai.security.repository.service.Impl;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import xyz.ibudai.security.core.model.vo.AuthUser;
import xyz.ibudai.security.repository.dao.AuthUserDao;
import xyz.ibudai.security.repository.service.AuthUserService;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * (TbUser)表服务实现类
 *
 * @author makejava
 * @since 2023 -01-31 14:31:28
 */
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthUserServiceImpl implements AuthUserService {

    private static final Map<String, AuthUser> userCaches = new ConcurrentHashMap<>();

    private final AuthUserDao authUserDao;


    /**
     * Spring Security logic
     *
     * @param username username
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String key = UUID.nameUUIDFromBytes(username.getBytes()).toString();
        AuthUser authUser = userCaches.get(key);
        if (Objects.isNull(authUser)) {
            authUser = authUserDao.queryByName(username);
            if (authUser == null) {
                throw new IllegalArgumentException("User [" + username + "] doesn't exist.");
            }
            userCaches.put(key, authUser);
        }
        return authUser;
    }
}
