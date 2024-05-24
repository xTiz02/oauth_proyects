package org.example.jasper.oauth2_jwt_login.model.repository;

import org.example.jasper.oauth2_jwt_login.model.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends MongoRepository<UserEntity, String>{

    UserEntity findByEmail(String username);
    UserEntity findByUserName(String username);
}
