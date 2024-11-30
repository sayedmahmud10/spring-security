
package com;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;


import java.util.Date;

@Component
public class JwtTokenProvider {

    private final String SECRET_KEY = "yoursecretkeyyoursecretkeyyoursecretkeyyoursecretkey"; // Secret key to sign the JWT

    public String generateToken(Authentication authentication) {
        // Generate JWT based on user details
           Map<String,String> map = new HashMap<>();
           map.put("subject", "here");
             Date now = new Date();
                   Date validity = new Date(now.getTime() + 86400000);

try{
    SignatureAlgorithm sa = SignatureAlgorithm.HS256;

        return Jwts.builder()
            .claim("hello", "world")
            .subject("jow")
            .issuer("me")
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(new SecretKeySpec(SECRET_KEY.getBytes(), sa.getJcaName()))
            .compact();
            }
            catch(Exception e){
            return e.getMessage();
            }
    }

    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        System.out.println(username);
        return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
    }

    public String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    private Claims parseClaims(String token) {
    SignatureAlgorithm sa = SignatureAlgorithm.HS256;
        return Jwts.parser()
                   .verifyWith(new SecretKeySpec(SECRET_KEY.getBytes(), sa.getJcaName()))
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();

    }



    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
        System.out.println(e.getMessage());
            return false;
        }
    }
}
