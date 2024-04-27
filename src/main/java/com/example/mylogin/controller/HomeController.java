package com.example.mylogin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {
    @Autowired
    OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    @GetMapping("/")
    public String home() {
        return "Hello, Home!";
    }

    @GetMapping("/secured1")
    public String secured() {
        //System.out.println(principal);
        //var auth = SecurityContextHolder.getContext().getAuthentication();
        //Jwt jwt = (Jwt) auth.getPrincipal();

        //System.out.println(jwt.getClaims());

        final DefaultOidcUser user = (DefaultOidcUser) SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();

        System.out.println("user = " + user.getName());

        return "Hello, Secured-1!";
    }

    @GetMapping("/secured2")
    public String secured2() {
        return "Hello, Secured-2!";
    }
}
