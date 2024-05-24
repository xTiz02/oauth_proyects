package org.example.demooauth2.service;

import org.example.demooauth2.model.dto.CreateAppUserDto;
import org.example.demooauth2.model.dto.MessageDto;
import org.example.demooauth2.model.entity.AppUser;
import org.example.demooauth2.model.entity.Role;
import org.example.demooauth2.repository.AppUserRepository;
import org.example.demooauth2.repository.RoleRepository;
import org.example.demooauth2.util.RoleName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AppUserService {

    @Autowired
    private  AppUserRepository appUserRepository;

    @Autowired
    private  RoleRepository repository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto){
        AppUser appUser = AppUser.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.getRoles().forEach(r -> {
            Role role = repository.findByRol(RoleName.valueOf(r))
                    .orElseThrow(()-> new RuntimeException("role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);
        return new MessageDto("user " + appUser.getUsername() + " saved");
    }
}
