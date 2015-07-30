package sales.security;

<<<<<<< HEAD
import org.springframework.http.MediaType;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.annotation.Resource;

/**
 * Created by taras on 28.07.15.
 */
@Controller
public class LoginController {

    @Resource(name = "sessionRegistry")
    private SessionRegistryImpl sessionRegistry;

    @RequestMapping(
            value = "/login/success")
    public String logged() {
        String message = "Login Successful!";
        return "redirect:/login?message="+message;
    }


    @RequestMapping(
            value = "/login")
    public String login(@RequestParam(required = false) String message, Model model) {
        model.addAttribute("message", message);
        return "index";
    }

    @RequestMapping(
            value = "/login/failure")
    public String failure() {
        String message = "Login Failure!";
        return "redirect:/login?message="+message;
    }

    @RequestMapping(
            value = "/logout/success")
    public String logout() {
        String message = "Logout Success!";
        return "redirect:/login?message="+message;
    }

    @RequestMapping(
            value = "/userstat",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public String userStats(Model model) {
        model.addAttribute("message", sessionRegistry.getAllPrincipals().size());
        return "temp";
    }
=======
/**
 * Created by taras on 29.07.15.
 */
public class LoginController {
>>>>>>> upstream/master
}
