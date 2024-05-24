package org.example.demooauth2.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document
public class GoogleUser {
    @Id
    private String id;
    private String email;
    private String name;
    private String givenName;
    private String familyName;
    private String pictureUrl;

    public static GoogleUser fromOauth2User(OAuth2User user){
        GoogleUser googleUser = GoogleUser.builder()
                .email(user.getName())
                .name(user.getAttributes().get("name").toString())
                .givenName(user.getAttributes().get("given_name").toString())
                .familyName(user.getAttributes().get("family_name").toString())
                .pictureUrl(user.getAttributes().get("picture").toString())
                .build();
        return googleUser;
    }

    @Override
    public String toString() {
        return "GoogleUser{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", name='" + name + '\'' +
                ", givenName='" + givenName + '\'' +
                ", familyName='" + familyName + '\'' +
                ", pictureUrl='" + pictureUrl + '\'' +
                '}';
    }
}
