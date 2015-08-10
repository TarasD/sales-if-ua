package sales.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;

/**
 * Created by taras on 10.08.15.
 */
public class AuthenticationUserDetails implements UserDetails {
    private Long id;
    private final String login;
    private final String passwordHash;
    private final boolean enabled;
    private HashSet<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();

    public AuthenticationUserDetails(User user) {
        this.login = user.getUsername();
        this.passwordHash = user.getPassword();
        this.enabled = user.isEnabled();
        this.grantedAuthorities.addAll(user.getAuthorities());
    }

    public Long getId() {
        return id;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
