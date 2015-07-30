package sales.users.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import sales.users.domain.User;
import sales.users.service.IUserService;

import java.util.List;

/**
 * Created by taras on 29.07.15.
 */
@RestController
@RequestMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {

    @Autowired
    private IUserService userService;

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/shop")
    public List<User> getAllShops(@RequestParam(required = false, value ="page", defaultValue = "0") int page,
                                  @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                                  @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        //
        return userService.findByRole("shop", page, amount, sortField);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/client")
    public List<User> getAllClients(@RequestParam(required = false, value ="page", defaultValue = "0") int page,
                                    @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                                    @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        //
        return userService.findByRole("client", page, amount, sortField);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/shop/{id}")
    public User getShop(@PathVariable("id") Long id) {
        //
        return userService.getShop(id);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/client/{id}")
    public User getClient(@PathVariable("id") Long id) {
        //
        return userService.getClient(id);
    }

    @RequestMapping(
            method = RequestMethod.POST,
            value = "/add",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public User addPerson(@RequestBody User user) {
        //
        return userService.addUser(user);
    }

    @RequestMapping(
            method = RequestMethod.PATCH,
            value = "/update/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public User updatePerson(@PathVariable("id") Long id, @RequestBody User user) {
        User dbUser = userService.getById(id);

        if(user.getFirstName() != null) dbUser.setFirstName(user.getFirstName());
        if(user.getLastName() != null) dbUser.setLastName(user.getLastName());
        if(user.getAddress() != null) dbUser.setAddress(user.getAddress());
        if(user.getEmail() != null) dbUser.setEmail(user.getEmail());
        if(user.getPhoneNumber() != null) dbUser.setPhoneNumber(user.getPhoneNumber());
        if(user.getPassword() != null) dbUser.setPassword(user.getPassword());

        return userService.addUser(dbUser);
    }


    @RequestMapping(
            method = RequestMethod.DELETE,
            value = "/delete/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public String deleteEmployee(@PathVariable("id") Long id) {
        //
        userService.deleteUser(id);
        return "done";
    }

    @RequestMapping(value = "/shop/{field}={value}",
            method = RequestMethod.GET)
    public List<User> filterShopBy(@PathVariable("field") String searchField,
                              @PathVariable("value") String value,
                              @RequestParam(required = false, value ="page", defaultValue = "0") int page,
                              @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                              @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        return userService.findBy("shop", searchField, value, page, amount, sortField);
    }

    @RequestMapping(value = "/client/{field}={value}",
            method = RequestMethod.GET)
    public List<User> filterClientBy(@PathVariable("field") String searchField,
                              @PathVariable("value") String value,
                              @RequestParam(required = false, value ="page", defaultValue = "0") int page,
                              @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                              @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        return userService.findBy("client" ,searchField, value, page, amount, sortField);
    }
}
