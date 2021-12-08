package com.atakanoguzdev.supportportall.resource;

import com.atakanoguzdev.supportportall.domain.User;
import com.atakanoguzdev.supportportall.exception.ExceptionHandling;
import com.atakanoguzdev.supportportall.exception.domain.EmailExistException;
import com.atakanoguzdev.supportportall.exception.domain.UserNotFoundException;
import com.atakanoguzdev.supportportall.exception.domain.UsernameExistException;
import com.atakanoguzdev.supportportall.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = {"/","/user"})
public class UserResource extends ExceptionHandling {
    private UserService userService;

    @Autowired
    public UserResource(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, UsernameExistException, EmailExistException {
        User newUser = userService.register(user.getFirstName(),user.getLastName(),user.getUserName(),user.getEmail());
        return new ResponseEntity<>(newUser, HttpStatus.OK);

    }
}
