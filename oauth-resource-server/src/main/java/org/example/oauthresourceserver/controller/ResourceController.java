package org.example.oauthresourceserver.controller;

import org.example.oauthresourceserver.dto.MessageDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/resource")
public class ResourceController {


    @GetMapping("/user")
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'OAUTH2_USER')")
    public ResponseEntity<MessageDto> user(Authentication authentication){
        return ResponseEntity.ok(new MessageDto("Hello " + authentication.getName()));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<MessageDto> admin(Authentication authentication){
        return ResponseEntity.ok(new MessageDto("Hello Mr. " + authentication.getName()));
    }
}
