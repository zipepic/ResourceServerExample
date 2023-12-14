package com.example.oauthresourceserver.controller;

import com.project.core.dto.UserProfileDTO;
import com.project.core.queries.user.FetchUserProfileDTOByUserIdQuery;
import org.axonframework.queryhandling.QueryGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    private final QueryGateway queryGateway;
    @Autowired
    public HomeController(QueryGateway queryGateway) {
        this.queryGateway = queryGateway;
    }

    @GetMapping("/")
    public String home() {
        return ("<h1>Welcome</h1>");
    }
    @GetMapping("/secured")
    public UserProfileDTO secured() {
        var query = FetchUserProfileDTOByUserIdQuery.builder()
                .userId(SecurityContextHolder.getContext().getAuthentication().getName())
                .build();
        var user = queryGateway.query(query, UserProfileDTO.class);
        return user.join();
    }
}
