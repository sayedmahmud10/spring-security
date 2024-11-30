package com.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.JwtTokenProvider;
import java.util.Arrays;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.beans.factory.annotation.Autowired;


@RestController
public class PublicController {

    @Autowired
    JwtTokenProvider jwtTokenProvider ;

    @GetMapping("/public/resource1")
    public String publicResource() {
        return "This is a public resource.";
    }

    @GetMapping("/public/resource2")
    public String anotherPublicResource() {
        return "This is another public resource.";
    }
    @GetMapping("/restricted")
    public String restrictedResource() {
        return "This is another public resource.";
    }

    @GetMapping("/resource2")
    public String otherPublicResource() {
        Authentication authentication = createAuthentication();
        String token = jwtTokenProvider.generateToken(authentication);
        return token;
    }


    public static Authentication createAuthentication() {
        // Define username
        String username = "testUser";

        // Define password (for demonstration purposes, typically passwords aren't stored in plain text)
        String password = "testPassword";

        // Define authorities (roles)
        var authorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN")
        );

        // Create an Authentication instance
        return new UsernamePasswordAuthenticationToken(username, password, authorities);
    }
}
