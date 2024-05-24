package org.example.jasper.oauth2_jwt_login.controller;

import org.example.jasper.oauth2_jwt_login.model.entity.UserDto;
import org.example.jasper.oauth2_jwt_login.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
@Controller
@RequestMapping("/user")
public class UserController {

//    @GetMapping("/user")
//    public Map<String, Object> getUser(@AuthenticationPrincipal OAuth2User oAuth2User) {
//        return oAuth2User.getAttributes();
//    }
    @Autowired
    private UserService userService;

    @GetMapping("/create")
    public String userCreate(Model model){
        model.addAttribute("user",new UserDto());

        return "signup";
    }
    @PostMapping("/create")
    public String userSave(@ModelAttribute("user") UserDto userDTO){
        userService.createUser(userDTO);
        return "redirect:/login";
    }
}
