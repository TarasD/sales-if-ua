package sales.roles.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import sales.roles.domain.Role;
import sales.roles.repository.RoleRepository;

/**
 * Created by taras on 29.07.15.
 */
@Service("roleService")
public class RoleService implements IRoleService{

    @Autowired
    private RoleRepository roleRepository;

    public Role getRoleById(Long id) {
        return roleRepository.findOne(id);
    }

    public Role getRoleByValue(String value) {
        return roleRepository.findByValue(value);
    }
}
