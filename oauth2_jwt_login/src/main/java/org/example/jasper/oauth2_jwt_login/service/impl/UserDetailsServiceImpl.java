package org.example.jasper.oauth2_jwt_login.service.impl;

import org.example.jasper.oauth2_jwt_login.model.entity.UserEntity;
import org.example.jasper.oauth2_jwt_login.model.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUserName(username);

        if (user != null) {

            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            user.getRoles().forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role.getName()));
            });
            return new User(
                    user.getUserName(),
                    user.getPassword(),
                    authorities
                    );
        }
        return null;
    }
}
