package sales.security;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;

/**
 * Created by taras on 30.07.15.
 */
public class SingleEntryFilter extends OncePerRequestFilter {
    // The URI where the user should be redirected
    private String redirectURI;
    // The URI that needs to be watched for
    private List<String> guardURI;

    @Resource(name="sessionRegistry")
    private SessionRegistry sessionRegistry;

    // Redirect strategy implementation as copied from the ConcurrentSessionFilter
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {

                // Flag to indicate if user has already logged-in and session is still valid
                Boolean hasLoggedIn = (Boolean) session.getAttribute("hasLoggedIn");

                if (hasLoggedIn != null) {
                    // Loop list. We might have multiple URIs to guard for!
                    for (String guard: guardURI) {
                        if (request.getRequestURI().equals(guard) == true ) {
                            // Force the user to the main page
                            redirectStrategy.sendRedirect(request, response, redirectURI);

                        }
                    }

                } else {
                    // User is accessing site for the first time
                    // Either he's old session has expired or he purposely logged-out
                    // This will only be removed once the session has expired
                    // If it doesn't expire the user will not be able to login again!
                    session.setAttribute("hasLoggedIn", new Boolean(true));

                    // Refreshes the internal lastRequest to the current date and time.
                    info.refreshLastRequest();
                }
            } else {
            }
        } else {
        }
        filterChain.doFilter(request, response);
    }

    /*public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        HttpSession session = request.getSession(false);

        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {
                if (info.isExpired()) {
                    // Expired - abort processing
                    doLogout(request, response);

                    String targetUrl = determineExpiredUrl(request, info);

                    if (targetUrl != null) {
                        redirectStrategy.sendRedirect(request, response, targetUrl);

                        return;
                    } else {
                        response.getWriter().print("This session has been expired (possibly due to multiple concurrent " +
                                "logins being attempted as the same user).");
                        response.flushBuffer();
                    }

                    return;
                } else {
                    // Non-expired - update last request date/time
                    info.refreshLastRequest();
                }
            }
        }

        chain.doFilter(request, response);
    }*/

    public String getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
    }

    public List<String> getGuardURI() {
        return guardURI;
    }

    public void setGuardURI(List<String> guardURI) {
        this.guardURI = guardURI;
    }
}
