package org.example.jasper.oauth2_jwt_login.model.repository;

import org.example.jasper.oauth2_jwt_login.model.entity.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
    Role findByName(String name);
}
