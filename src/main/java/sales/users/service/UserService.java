package sales.users.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import sales.roles.domain.Role;
import sales.roles.service.RoleService;
import sales.users.domain.User;
import sales.users.repository.UserRepository;

import java.util.List;

/**
 * Created by taras on 29.07.15.
 */
@Service("userService")
public class UserService implements IUserService{

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleService roleService;

    @Override
    public User getByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User getById(Long id) {
        return userRepository.getOne(id);
    }

    @Override
    public User getShop(Long id) {
        return userRepository.findByRoleAndId(roleService.getRoleByValue("shop"), id);
    }

    @Override
    public User getClient(Long id) {
        return userRepository.findByRoleAndId(roleService.getRoleByValue("user"), id);
    }

    @Override
    public User addUser(User shop) {
        return null;
    }

    @Override
    public void deleteUser(Long id) {

    }

    @Override
    public List<User> findBy(String roleValue, String searchField, String value, int page, int amount, String sortField) {
        Sort sort = new Sort(Sort.Direction.ASC, sortField);
        PageRequest pageRequest = new PageRequest(page, amount, sort);
        Role role = roleService.getRoleByValue(roleValue);

        if(searchField.equals("username")) return userRepository.findByRoleAndUsername(role, value, pageRequest).getContent();
        else if(searchField.equals("firstName")) return userRepository.findByRoleAndFirstName(role, value, pageRequest).getContent();
        else if(searchField.equals("lastName")) return userRepository.findByRoleAndLastName(role, value, pageRequest).getContent();
        else if(searchField.equals("address")) return userRepository.findByRoleAndAddress(role, value, pageRequest).getContent();
        else if(searchField.equals("email")) return userRepository.findByRoleAndEmail(role, value, pageRequest).getContent();
        else if(searchField.equals("phoneNumber")) return userRepository.findByRoleAndPhoneNumber(role, value, pageRequest).getContent();
        return null;
    }

    @Override
    public List<User> findByRole(String roleValue, int page, int amount, String sortField) {
        Sort sort = new Sort(Sort.Direction.ASC, sortField);
        PageRequest pageRequest = new PageRequest(page, amount, sort);

        Role role = roleService.getRoleByValue(roleValue);

        return userRepository.findByRole(role, pageRequest).getContent();
    }
}
