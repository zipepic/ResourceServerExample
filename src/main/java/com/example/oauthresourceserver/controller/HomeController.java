package com.example.oauthresourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping("/")
    public String home() {
        return ("<h1>Welcome</h1>");
    }
    @GetMapping("/secured")
    public String secured() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ("<h1>Secured</h1> " + authentication.getName());
    }
}
