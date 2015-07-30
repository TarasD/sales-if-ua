package sales.users.service;

import sales.users.domain.User;

import java.util.List;

/**
 * Created by taras on 29.07.15.
 */
public interface IUserService {
/*
    List<User> getAll(int page, int amount, String field);
*/

    User getById(Long id);

    User getByUsername(String username);

    User getShop(Long id);

    User getClient(Long id);

    User addUser(User user);

    void deleteUser(Long id);

    List<User> findBy(String roleValue ,String searchField, String value, int page, int amount, String sortField);

    List<User> findByRole(String roleValue, int page, int amount, String sortField);
}
