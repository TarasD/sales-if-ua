package sales.users.controller;

import com.wordnik.swagger.annotations.ApiOperation;
import com.wordnik.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sales.users.domain.User;
import sales.users.service.UserService;
import sales.util.Constants;

import java.util.List;

/**
 * Created by taras on 29.07.15.
 */
@RestController
@RequestMapping(value = "/user")
public class UserController {
    final static Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @RequestMapping(
            method = RequestMethod.GET,
            value = "",
            produces = "application/json")
    public User getUserByEncEmail(@RequestParam(required = true, value ="email") String email) {
        logger.info("Get user by email");
        return userService.getByEncEmail(email);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/{id}",
            produces = "application/json")
    public User getUser(@PathVariable("id") Long id) {
        logger.info("Get client by id");
        return userService.getById(id);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/shop",
            produces = "application/json")
    public List<User> getAllShops(@RequestParam(required = false, value ="page", defaultValue = "0") int page,
                                  @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                                  @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        logger.info("Get pageable list of shops");
        return userService.findByRole(Constants.SHOP, page, amount, sortField);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/client",
            produces = "application/json")
    public List<User> getAllClients(@RequestParam(required = false, value ="page", defaultValue = "0") int page,
                                    @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                                    @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        logger.info("Get pageable list of clients");
        return userService.findByRole("client", page, amount, sortField);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/shop/{id}",
            produces = "application/json")
    public User getShop(@PathVariable("id") Long id) {
        logger.info("Get Shop by id");
        return userService.getShop(id);
    }

    @RequestMapping(
            method = RequestMethod.GET,
            value = "/client/{id}",
            produces = "application/json")
    public User getClient(@PathVariable("id") Long id) {
        logger.info("Get client by id");
        return userService.getClient(id);
    }

    @RequestMapping(
            method = RequestMethod.POST,
            value = "",
            consumes= "application/json",
            produces = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public User addPerson(@RequestBody User user) {
        logger.info("Add user");
        return userService.addUser(user);
        //return null;
    }

    @RequestMapping(
            method = RequestMethod.PATCH,
            value = "/{id}",
            consumes= "application/json",
            produces = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public User updatePerson(@PathVariable("id") Long id, @RequestBody User user) {
        logger.info("Update User with id = " + id);
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
            value = "/{id}",
            produces = "application/json")
    @ResponseStatus(HttpStatus.OK)
    public void deleteUser(@PathVariable("id") Long id) {
        logger.info("Delete user with id = " + id);
        userService.deleteUser(id);
    }

    @RequestMapping(value = "/shop/filter",
            method = RequestMethod.GET,
            produces = "application/json")
    public List<User> filterShopBy(@RequestParam(value = "field") String searchField,
                              @RequestParam(value = "value") String value,
                              @RequestParam(required = false, value ="page", defaultValue = "0") int page,
                              @RequestParam(required = false, value = "amount", defaultValue = "5") int amount,
                              @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        logger.info("Filter Shops by " + searchField + " = " + value);
        return userService.findBy("shop", searchField, value, page, amount, sortField);
    }

    @RequestMapping(value = "/client/filter",
            method = RequestMethod.GET,
            produces = "application/json")
    public List<User> filterClientBy(@RequestParam(value = "field") String searchField,
                              @RequestParam(value = "value") String value,
                              @RequestParam(required = false, value ="page", defaultValue = "0") int page,
                              @RequestParam(required = false, value = "amount", defaultValue = "1") int amount,
                              @RequestParam(required = false, value = "sort", defaultValue = "id") String sortField) {
        logger.info("Filter Clients by " + searchField + " = " + value);
        return userService.findBy("client" ,searchField, value, page, amount, sortField);
    }

    @ApiOperation(httpMethod = "PUT",
            value = "Change user lock status",
            notes = "New user status: isBlockedNew = !isBlockedOld")
    @RequestMapping(value = "/lock/{userId}",
                    method = RequestMethod.PUT)
    public ResponseEntity<String> changeUserLock(@ApiParam(value = "Id of user, which lockStatus have to be changed", required = true)
                                                 @PathVariable(value = "userId") Long userId)
    {
        if (userService.changeUserLock(userId)) {
            return new ResponseEntity<String>("User !locked", HttpStatus.OK);
        } else {
            return new ResponseEntity<String>("User does not exist", HttpStatus.BAD_REQUEST);
        }

    }
}
