package com.bolsadeideas.springboot.app.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Collection;

public interface JWTService {
    public String create(Authentication authentication) throws IOException;

    public boolean validate(String token);

    public Claims getClaims(String token);

    public String getUserName(String token);

    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException;

    public String resolve(String token);

}
