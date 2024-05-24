package org.example.jasper.oauth2_jwt_login.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/home")
public class HomeController {

    @GetMapping
    public ResponseEntity<String> getHomePage(){
        return ResponseEntity.ok().body(
                "Welcome to Api End point"
        );
    }
}
