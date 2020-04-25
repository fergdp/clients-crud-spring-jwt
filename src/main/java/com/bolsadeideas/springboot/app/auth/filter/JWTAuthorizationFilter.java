package com.bolsadeideas.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader("Authorization");

        if (!requiresAuthentication(header)) {
            chain.doFilter(request, response);
            return;
        }

        boolean validoToken;
        Claims token = null;
        try {
            token = Jwts.parser()
                    .setSigningKey("Alguna.Clave.Secreta.123456".getBytes())
                    .parseClaimsJws(header.replace("Barer ", "")).getBody();
            validoToken = true;
        } catch (JwtException | IllegalArgumentException e) {
            validoToken = false;
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;

        if (validoToken) {
            String userName = token.getSubject();
            Object roles = token.get("authorities");

            Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper().readValue(roles.toString(), SimpleGrantedAuthority[].class));

            usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userName, null, authorities);
        }

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        chain.doFilter(request,response);
    }

    private boolean requiresAuthentication(String header) {
        if (header == null || !header.startsWith("Barer ")) {
            return false;
        }
        return true;
    }
}
