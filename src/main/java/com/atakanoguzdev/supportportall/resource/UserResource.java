package com.atakanoguzdev.supportportall.resource;

import com.atakanoguzdev.supportportall.domain.User;
import com.atakanoguzdev.supportportall.domain.UserPrincipal;
import com.atakanoguzdev.supportportall.exception.ExceptionHandling;
import com.atakanoguzdev.supportportall.exception.domain.EmailExistException;
import com.atakanoguzdev.supportportall.exception.domain.UserNotFoundException;
import com.atakanoguzdev.supportportall.exception.domain.UsernameExistException;
import com.atakanoguzdev.supportportall.service.UserService;
import com.atakanoguzdev.supportportall.utility.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;

import java.io.IOException;
import java.util.List;

import static com.atakanoguzdev.supportportall.constant.SecurityConstant.JWT_TOKEN_HEADER;

@RestController
@RequestMapping(path = {"/","/user"})
public class UserResource extends ExceptionHandling {
    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JWTTokenProvider jwtTokenProvider;

    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        authenticate(user.getUserName(), user.getPassword());
        User loginUser = userService.findUserByUserName(user.getUserName());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, HttpStatus.OK);

    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, UsernameExistException, EmailExistException, MessagingException {
        User newUser = userService.register(user.getFirstName(),user.getLastName(),user.getUserName(),user.getEmail());
        return new ResponseEntity<>(newUser, HttpStatus.OK);

    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNonLocked") String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        User newUser = userService.addNewUser(firstName,lastName,username,email,role,Boolean.parseBoolean(isActive),Boolean.parseBoolean(isNonLocked),profileImage);
        return new ResponseEntity<>(newUser,HttpStatus.OK);

    }

    @PostMapping("/update")
    public ResponseEntity<User> update(@RequestParam("firstName") String firstName,
                                       @RequestParam("currentUsername") String currentUsername,
                                       @RequestParam("lastName") String lastName,
                                       @RequestParam("username") String username,
                                       @RequestParam("email") String email,
                                       @RequestParam("role") String role,
                                       @RequestParam("isActive") String isActive,
                                       @RequestParam("isNonLocked") String isNonLocked,
                                       @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        User updateUser = userService.updateUser(currentUsername,firstName,lastName,username,email,role,Boolean.parseBoolean(isActive),Boolean.parseBoolean(isNonLocked),profileImage);
        return new ResponseEntity<>(updateUser,HttpStatus.OK);
    }

    @GetMapping("find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username) {
        User user = userService.findUserByUserName(username);
        return new ResponseEntity<>(user,HttpStatus.OK);
    }

    @GetMapping("find/{username}")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users,HttpStatus.OK);
    }

    private HttpHeaders getJwtHeader(UserPrincipal user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));
        return headers;
    }

    private void authenticate(String userName, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName,password));
    }

}
