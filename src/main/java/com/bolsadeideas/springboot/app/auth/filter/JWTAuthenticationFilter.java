package com.bolsadeideas.springboot.app.auth.filter;

import com.bolsadeideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if(username != null && password != null) {
            logger.info("Username desde request parameter (form-adata): " + username);
            logger.info("Password desde request parameter (form-adata): " + password);
        } else {
            Usuario user = null;
            try {
                user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
                username = user.getUsername();
                password = user.getPassword();

                logger.info("Username desde request parameter (form-adata): " + username);
                logger.info("Password desde request parameter (form-adata): " + password);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authTokern = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authTokern);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String userName  = ((User)authResult.getPrincipal()).getUsername();

        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .signWith(secretKey)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() * 14000000L))
                .compact();

        response.addHeader("Authorization", "Bearer " + token);

        Map<String, Object> body =  new HashMap<String, Object>();
        body.put("token", token);
        body.put("user", (User)authResult.getPrincipal());
        body.put("mensaje", String.format("Hola %s, Has iniciado sesión con éxito", userName));

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }
}
