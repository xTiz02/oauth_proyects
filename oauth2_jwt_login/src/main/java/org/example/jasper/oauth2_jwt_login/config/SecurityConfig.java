package org.example.jasper.oauth2_jwt_login.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.jasper.oauth2_jwt_login.service.impl.OauthUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private OauthUserServiceImpl oauthUserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests(request->
                        request.requestMatchers("/user/create","/login","/css/**",
                                        "/js/**","/images/**").permitAll()
                                .anyRequest().authenticated())
                .formLogin(form-> form.loginPage("/login")//indicamos que la pagina de login es /login y no la que spring security por defecto
                        .defaultSuccessUrl("/",true))
                .oauth2Login(oauth2->oauth2
                        .loginPage("/login")//loginPage es para que no se abra la ventana de login de google por defecto y se abra la ventana de login de la app
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oauthUserService)))
                .build();

//        return http
//                .authorizeHttpRequests(request ->
//                        request.anyRequest().authenticated())
//                .oauth2Login(oauth2 -> //por defecto abre una ventana de login de google porque es el proveedor por defecto en spring security
//                        oauth2.defaultSuccessUrl("/user", true))
//                .build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    * @Configuration
public class WebConfig {

    @Bean
    public WebMvcConfigurer corsConfig() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("GET", "POST", "OPTIONS")
                        .allowedOrigins("http://localhost:4200");
            }
        };
    }
}*/
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId("google")
//                .clientId("google-client-id")
//                .clientSecret("google-client-secret")
//                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://localhost:8080/login/oauth2/code/google")
//                .scope(OidcScopes.OPENID)
//                .clientName("Google")
//                .build();
//        return null;
//    }

}
