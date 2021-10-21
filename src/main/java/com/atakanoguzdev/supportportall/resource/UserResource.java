package com.atakanoguzdev.supportportall.resource;

import com.atakanoguzdev.supportportall.domain.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/user")
public class UserResource {

    @GetMapping("/home")
    public String showUser(){
        return "application works";
    }
}
