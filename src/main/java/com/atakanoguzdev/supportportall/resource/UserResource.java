package com.atakanoguzdev.supportportall.resource;

import com.atakanoguzdev.supportportall.domain.User;
import com.atakanoguzdev.supportportall.exception.ExceptionHandling;
import com.atakanoguzdev.supportportall.exception.domain.EmailExistException;
import com.atakanoguzdev.supportportall.exception.domain.UserNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = {"/","/user"})
public class UserResource extends ExceptionHandling {

    @GetMapping("/home")
    public String showUser() throws UserNotFoundException {
        //return "application works";
        throw new UserNotFoundException("The user not found.");
    }
}
