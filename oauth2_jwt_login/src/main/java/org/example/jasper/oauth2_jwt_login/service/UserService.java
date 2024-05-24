package org.example.jasper.oauth2_jwt_login.service;

import org.example.jasper.oauth2_jwt_login.model.entity.UserDto;

import java.util.List;

public interface UserService {
    UserDto createUser(UserDto userDto);
    List<UserDto> findAllUsers();
}
