package org.example.jasper.oauth2_jwt_login;

import org.example.jasper.oauth2_jwt_login.model.entity.Role;
import org.example.jasper.oauth2_jwt_login.model.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Oauth2JwtLoginApplication implements CommandLineRunner {
    @Autowired
    private RoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(Oauth2JwtLoginApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
//        roleRepository.save(new Role(null,"ROLE_USER"));
//        roleRepository.save(new Role(null,"ROLE_ADMIN"));
    }
}
