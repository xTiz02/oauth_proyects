package org.example.demooauth2.controller;

import org.example.demooauth2.model.dto.CreateClientDto;
import org.example.demooauth2.model.dto.MessageDto;
import org.example.demooauth2.service.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client")
public class ClientController {

    @Autowired
    private ClientService clientService;

    @PostMapping("/create")
    public ResponseEntity<MessageDto> create(@RequestBody CreateClientDto dto){
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.create(dto));
    }
}
