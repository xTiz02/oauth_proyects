package org.example.jasper.oauth2_jwt_login.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private String id;
    private String firstName;
    private String lastName;
    private String userName;
    private String password;
    private String provider;
    private String email;
    private String providerId;
    private String imageUrl;
    private String confirmPassword;
    private boolean emailVerified;
    private List<String> roles;


    public static UserEntity convertToEntity(UserDto userDto) {
        UserEntity userEntity = new UserEntity();
        userEntity.setFirstName(userDto.getFirstName());
        userEntity.setLastName(userDto.getLastName());
        userEntity.setUserName(userDto.getUserName());
        userEntity.setPassword(userDto.getPassword());
        return userEntity;
    }
}
