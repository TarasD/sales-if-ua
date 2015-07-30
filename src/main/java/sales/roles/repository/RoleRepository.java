package sales.roles.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.roles.domain.Role;

/**
 * Created by taras on 29.07.15.
 */
public interface RoleRepository extends JpaRepository<Role, Long>{
    Role findByValue(String value);
}
