package sales.roles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;
import sales.roles.domain.Role;
import sales.roles.service.IRoleService;
import sales.roles.service.RoleService;

/**
 * Created by taras on 29.07.15.
 */
@RestController
public class RoleController {

    @Autowired
    private IRoleService roleService;

    public Role getRole(Long id) {
        return roleService.getRoleById(id);
    }
}
