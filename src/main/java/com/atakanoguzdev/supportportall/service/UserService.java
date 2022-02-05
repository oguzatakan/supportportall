package com.atakanoguzdev.supportportall.service;

import com.atakanoguzdev.supportportall.domain.User;
import com.atakanoguzdev.supportportall.exception.domain.EmailExistException;
import com.atakanoguzdev.supportportall.exception.domain.EmailNotFoundException;
import com.atakanoguzdev.supportportall.exception.domain.UserNotFoundException;
import com.atakanoguzdev.supportportall.exception.domain.UsernameExistException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

@Service
public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException, MessagingException;

    List<User> getUsers();

    User findUserByUserName(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    User updateUser(String currentUserName,String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    void deleteUser (long id);

    void resetPassword (String email) throws MessagingException, EmailNotFoundException;

    User updateProfileImage(String username,MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
}
