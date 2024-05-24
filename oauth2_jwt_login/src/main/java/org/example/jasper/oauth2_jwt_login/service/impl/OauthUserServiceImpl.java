package org.example.jasper.oauth2_jwt_login.service.impl;

import lombok.RequiredArgsConstructor;
import org.example.jasper.oauth2_jwt_login.config.AuthorizationServerConfig;
import org.example.jasper.oauth2_jwt_login.model.entity.UserDto;
import org.example.jasper.oauth2_jwt_login.model.entity.UserEntity;
import org.example.jasper.oauth2_jwt_login.model.repository.RoleRepository;
import org.example.jasper.oauth2_jwt_login.model.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OauthUserServiceImpl extends DefaultOAuth2UserService {
    //TokenService tokenService;
    //RegisteredClientRepository
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        processOAuth2User(userRequest, super.loadUser(userRequest));
        System.out.println("User info is " + oAuth2User.getAttributes());
//        System.out.println("User request is " + userRequest.getAccessToken().getTokenValue());
//        System.out.println("User request is " + userRequest.getAccessToken().getExpiresAt());
//        System.out.println("User request is " + userRequest.getAccessToken().getScopes());
//        System.out.println("User request is " + userRequest.getClientRegistration().getClientId());
//        for (Map.Entry<String, Object> map : userRequest.getAdditionalParameters().entrySet()) {
//            System.out.println("User request is " + map.getKey() + " " + map.getValue());
//        }
        return super.loadUser(userRequest);
    }
    private void processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        UserDto userDto = new UserDto();
        userDto.setProvider(oAuth2UserRequest.getClientRegistration().getRegistrationId());
        userDto.setProviderId(oAuth2User.getAttribute("sub"));
        userDto.setFirstName(oAuth2User.getAttribute("given_name"));
        userDto.setLastName(oAuth2User.getAttribute("family_name"));
        userDto.setEmail(oAuth2User.getAttribute("email"));
        userDto.setImageUrl(oAuth2User.getAttribute("picture"));
        userDto.setEmailVerified(oAuth2User.getAttribute("email_verified"));

        UserEntity userOptional = userRepository.findByEmail(userDto.getEmail());
        if (userOptional != null) {
            updateExistingUser(userOptional, userDto);
        } else {
            registerNewUser(oAuth2UserRequest, userDto);
        }
    }

    private UserEntity registerNewUser(OAuth2UserRequest oAuth2UserRequest, UserDto userInfoDto) {
        UserEntity user = new UserEntity();
        user.setProvider(oAuth2UserRequest.getClientRegistration().getRegistrationId());
        user.setProviderId(userInfoDto.getProviderId());
        user.setFirstName(userInfoDto.getFirstName());
        user.setLastName(userInfoDto.getLastName());
        user.setEmailVerified(userInfoDto.isEmailVerified());
        user.setEmail(userInfoDto.getEmail());
        user.setImageUrl(userInfoDto.getImageUrl());
        user.setRoles(List.of(roleRepository.findByName("ROLE_USER")));
        return userRepository.save(user);
    }

    private UserEntity updateExistingUser(UserEntity existingUser, UserDto userInfoDto) {
        existingUser.setFirstName(userInfoDto.getFirstName());
        existingUser.setLastName(userInfoDto.getLastName());
        existingUser.setImageUrl(userInfoDto.getImageUrl());
        existingUser.setEmail(userInfoDto.getEmail());
        existingUser.setEmailVerified(userInfoDto.isEmailVerified());
        return userRepository.save(existingUser);
    }
}
