package com.programming.techie.springngblog.security;

import com.programming.techie.springngblog.exception.SpringBlogException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

@Service
public class JwtProvider {

    private KeyStore keyStore;
    @PostConstruct
    public void init(){
        try {
            keyStore = KeyStore.getInstance("JKS");
            InputStream resourceStream = getClass().getResourceAsStream("/springblog.jks");
            keyStore.load(resourceStream,"kerem123".toCharArray());
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new SpringBlogException("Exception occured while laoding keystore");
        }
    }


    public String generateToken(Authentication authentication){
        User principal = (User) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(principal.getUsername())
                .signWith(getPrivateKey())
                .compact();
    }

    private Key getPrivateKey() {
        try {
            return (PrivateKey) keyStore.getKey("springblog","kerem123".toCharArray());
        } catch (UnrecoverableKeyException |KeyStoreException | NoSuchAlgorithmException e) {
            throw new SpringBlogException("exception occured while retrieving public key from keystore");
        }
    }

    public boolean validateToken(String jwt){
        Jwts.parser().setSigningKey(getPublicKey())
                .parseClaimsJws(jwt);
        return true;
    }

    private PublicKey getPublicKey() {
        try {
            return keyStore.getCertificate("springblog").getPublicKey();
        } catch (KeyStoreException e) {
            throw new SpringBlogException("exception occured while retrieving public key from keystore");
        }
    }

    public String getUsernameFromJWT(String jwt) {
        Claims claims = Jwts.parser()
                        .setSigningKey(getPublicKey())
                        .parseClaimsJws(jwt)
                        .getBody();
        return claims.getSubject();
    }
}
