package org.example.jasper.oauth2_jwt_login.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
public class UserEntity {

    @Id
    private String id;
    private String firstName;
    private String lastName;
    private String userName;
    private String password;
    private String email;
    private String providerId;
    private String imageUrl;
    private String provider;
    private boolean emailVerified;
    @DBRef
    private List<Role> roles;

    public static UserDto convertToDto(UserEntity userEntity) {
        UserDto userDto = new UserDto();
        userDto.setFirstName(userEntity.getFirstName());
        userDto.setLastName(userEntity.getLastName());
        userDto.setUserName(userEntity.getUserName());
        userDto.setPassword(userEntity.getPassword());
        userDto.setEmail(userEntity.getEmail());
        userDto.setProviderId(userEntity.getProviderId());
        userDto.setImageUrl(userEntity.getImageUrl());
        userDto.setProvider(userEntity.getProvider());
        userDto.setEmailVerified(userEntity.isEmailVerified());
        userDto.setRoles(userEntity.getRoles().stream().map(Role::getName).toList());
        return userDto;
    }

}
