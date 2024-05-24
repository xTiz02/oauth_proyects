package org.example.demooauth2.repository;

import org.example.demooauth2.model.entity.Client;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends MongoRepository<Client, String>{
    Optional<Client> findByClientId(String clientId);
}
