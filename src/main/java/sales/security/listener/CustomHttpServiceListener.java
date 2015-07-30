package sales.security.listener;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * Created by taras on 30.07.15.
 */
public class CustomHttpServiceListener implements HttpSessionListener {

    private static int totalActiveSessions;

    public static int getTotalActiveSessions() {
        return totalActiveSessions;
    }

    @Override
    public void sessionCreated(HttpSessionEvent httpSessionEvent) {
        httpSessionEvent.getSession().setMaxInactiveInterval(30*60);
        totalActiveSessions++;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
        totalActiveSessions--;
    }
}
