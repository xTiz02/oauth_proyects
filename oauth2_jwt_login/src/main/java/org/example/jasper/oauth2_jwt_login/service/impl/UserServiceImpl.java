package org.example.jasper.oauth2_jwt_login.service.impl;

import org.example.jasper.oauth2_jwt_login.model.entity.UserDto;
import org.example.jasper.oauth2_jwt_login.model.entity.UserEntity;
import org.example.jasper.oauth2_jwt_login.model.repository.RoleRepository;
import org.example.jasper.oauth2_jwt_login.model.repository.UserRepository;
import org.example.jasper.oauth2_jwt_login.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private BCryptPasswordEncoder encoder;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDto createUser(UserDto userDTO) {
        UserEntity userToSave = UserDto.convertToEntity(userDTO);
        userToSave.setPassword(encoder.encode(userToSave.getPassword()));
        userToSave.setRoles(List.of(roleRepository.findByName("ROLE_USER")));
        UserEntity savedUser = userRepository.save(userToSave);
        return UserEntity.convertToDto(savedUser);
    }

    @Override
    public List<UserDto> findAllUsers() {
        List<UserEntity> users = userRepository.findAll();
        return users.stream().map(UserEntity::convertToDto).collect(Collectors.toList());
    }
}
