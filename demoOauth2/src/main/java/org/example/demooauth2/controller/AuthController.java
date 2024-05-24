package org.example.demooauth2.controller;

import org.example.demooauth2.model.dto.CreateAppUserDto;
import org.example.demooauth2.service.AppUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AppUserService appUserService;

    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody CreateAppUserDto createAppUserDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.createUser(createAppUserDto));
    }
}
