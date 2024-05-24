package org.example.demooauth2.repository;

import org.example.demooauth2.model.entity.Role;
import org.example.demooauth2.util.RoleName;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends MongoRepository<Role, Long>{
    Optional<Role> findByRol(RoleName rol);
}
