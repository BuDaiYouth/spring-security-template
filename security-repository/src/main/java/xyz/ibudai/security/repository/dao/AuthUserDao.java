package xyz.ibudai.security.repository.dao;

import xyz.ibudai.security.core.model.vo.AuthUser;

/**
 * (TbUser)表数据库访问层
 *
 * @author makejava
 * @since 2023-01-31 14:31:28
 */
public interface AuthUserDao {

    /**
     * 通过ID查询单条数据
     *
     * @param id 主键
     * @return 实例对象
     */
    AuthUser queryById(String id);

    /**
     * Query by name tb user.
     *
     * @param userName the username
     * @return the tb user
     */
    AuthUser queryByName(String userName);

}

