package org.example.demooauth2.repository;

import org.example.demooauth2.model.entity.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepository extends MongoRepository<AppUser, Integer>{
    Optional<AppUser> findByUsername(String username);
}
