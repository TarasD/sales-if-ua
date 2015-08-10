package sales.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import sales.users.domain.User;
import sales.users.repository.UserRepository;

/**
 * Created by taras on 10.08.15.
 */
public class SpringSecurityUserLoginService implements UserLoginService {
    final static Logger logger = LoggerFactory.getLogger(SpringSecurityUserLoginService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    private AuthenticationManager authenticationManager;
    private static final String internalHashKeyForAutomaticLoginAfterRegistration = "magicInternalHashKeyForAutomaticLoginAfterRegistration";

    public SpringSecurityUserLoginService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public boolean login(String login, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, password));
        boolean isAuthenticated = isAuthenticated(authentication);
        if (isAuthenticated) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        return isAuthenticated;
    }

    @Override
    public boolean login(Long userId) {
        boolean isLoginSuccesfull = false;
        User user = userRepository.findOne(userId);
        if (user != null) {
            AuthenticationUserDetails userDetails = customUserDetailsService.loadUserByUsername(user.getEmail());
            final RememberMeAuthenticationToken rememberMeAuthenticationToken = new RememberMeAuthenticationToken(internalHashKeyForAutomaticLoginAfterRegistration, userDetails, null);
            rememberMeAuthenticationToken.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(rememberMeAuthenticationToken);
            isLoginSuccesfull = true;
        }
        return isLoginSuccesfull;
    }


    @Override
    public void logout() {
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Override
    public boolean isLoggedIn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return isAuthenticated(authentication);
    }

    @Override
    public AuthenticationUserDetails getLoggedUserDetails() {
        AuthenticationUserDetails loggedUserDetails = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (isAuthenticated(authentication)) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof AuthenticationUserDetails) {
                loggedUserDetails = ((AuthenticationUserDetails) principal);
            } else {
                logger.error("Expected class of authentication principal is AuthenticationUserDetails. Given: " + principal.getClass());
            }
        }
        return loggedUserDetails;
    }


    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null && !(authentication instanceof AnonymousAuthenticationToken) && authentication.isAuthenticated();
    }

    @Override
    public User getLoggedUser() {
        User loggedUser = null;
        AuthenticationUserDetails userDetails = getLoggedUserDetails();
        if (userDetails != null) {
            loggedUser = userRepository.findOne(userDetails.getId());
        }
        return loggedUser;
    }
}
