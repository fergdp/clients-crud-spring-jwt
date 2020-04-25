package com.bolsadeideas.springboot.app.auth.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JWTServiceImpl implements JWTService{
    @Override
    public String create(Authentication authentication) {
        return null;
    }

    @Override
    public boolean validate(String token) {
        return false;
    }

    @Override
    public Claims getClaims(String token) {
        return null;
    }

    @Override
    public String getUserName(String token) {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getRoles() {
        return null;
    }

    @Override
    public String resolve(String token) {
        return null;
    }
}
