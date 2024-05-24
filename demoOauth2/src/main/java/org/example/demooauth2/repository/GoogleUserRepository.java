package org.example.demooauth2.repository;

import org.example.demooauth2.model.entity.GoogleUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface GoogleUserRepository extends MongoRepository<GoogleUser, String> {
    Optional<GoogleUser> findByEmail(String s);

}
