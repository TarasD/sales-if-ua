package sales.users.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import sales.roles.domain.Role;
import sales.users.domain.User;

/**
 * Created by taras on 29.07.15.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Page<User> findByRole(Role role, Pageable pageable);

    User findByRoleAndId(Role role, Long id);

    User findByUsername(String username);

    Page<User> findByRoleAndUsername(Role role, String username, Pageable pageable);

    Page<User> findByRoleAndFirstName(Role role, String firstName, Pageable pageable);

    Page<User> findByRoleAndLastName(Role role, String lastName, Pageable pageable);

    Page<User> findByRoleAndAddress(Role role, String address, Pageable pageable);

    Page<User> findByRoleAndEmail(Role role, String email, Pageable pageable);

    Page<User> findByRoleAndPhoneNumber(Role role, String phoneNumber, Pageable pageable);
}
