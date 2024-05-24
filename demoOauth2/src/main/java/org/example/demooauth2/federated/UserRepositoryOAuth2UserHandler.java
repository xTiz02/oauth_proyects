package org.example.demooauth2.federated;

import lombok.extern.slf4j.Slf4j;
import org.example.demooauth2.model.entity.GoogleUser;
import org.example.demooauth2.repository.GoogleUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@Service
@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {


    private final GoogleUserRepository googleUserRepository;

    public  UserRepositoryOAuth2UserHandler(GoogleUserRepository googleUserRepository) {
        this.googleUserRepository = googleUserRepository;
    }

    @Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        user.getAttributes().forEach((k,v)-> System.out.println(k + " : " + v));
        user.getAuthorities().forEach(System.out::println);
        if (!this.googleUserRepository.findByEmail(user.getName()).isPresent()) {
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
            log.info(googleUser.toString());
            this.googleUserRepository.save(googleUser);
        } else {
            log.info("bienvenido {}", user.getAttributes().get("given_name"));
        }
    }

}
