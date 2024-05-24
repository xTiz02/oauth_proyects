package org.example.demooauth2;

import org.example.demooauth2.model.entity.Role;
import org.example.demooauth2.repository.RoleRepository;
import org.example.demooauth2.service.ClientService;
import org.example.demooauth2.util.RoleName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@SpringBootApplication
public class DemoOauth2Application implements CommandLineRunner{

    @Autowired
    private ClientService clientService;

    public static void main(String[] args) {
        SpringApplication.run(DemoOauth2Application.class, args);
    }

    @Override
	public void run(String... args) throws Exception {
//		Role adminRole = Role.builder().rol(RoleName.ROLE_ADMIN).build();
//		Role userRole = Role.builder().rol(RoleName.ROLE_USER).build();
//		repository.save(adminRole);
//		repository.save(userRole);
        RegisteredClient rc = clientService.findByClientId("client");
        System.out.println(rc.toString());
        rc.getAuthorizationGrantTypes().forEach(g -> System.out.println(g.getValue()));
	}

}
