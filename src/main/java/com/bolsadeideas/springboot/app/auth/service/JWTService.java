package com.bolsadeideas.springboot.app.auth.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface JWTService {
    public String create(Authentication authentication);

    public boolean validate(String token);

    public Claims getClaims(String token);

    public String getUserName(String token);

    public Collection<? extends GrantedAuthority> getRoles();

    public String resolve(String token);

}
