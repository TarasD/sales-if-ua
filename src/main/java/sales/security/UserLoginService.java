package sales.security;

import sales.users.domain.User;

/**
 * Created by taras on 10.08.15.
 */
public interface UserLoginService {

    User getLoggedUser();

    AuthenticationUserDetails getLoggedUserDetails();

    boolean login(Long userId);

    boolean login(String login, String password);
    void logout();
    boolean isLoggedIn();

}
