package com.springSecurity.jwtAuthentication.webtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class JwtService {
    //the test directory is used to generate the secret key
    public static final String SECRET = "4C56EE5BD1A560FE059CA7AE99B61EDF3E4EFA60D3957A555F546812B55A8920AE0548A9EF27D7A4545529C58003894BADC8B4C9FAEE3E6EC34C8144E8300169";
    private static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);

    //this method is to be called when a login is requested from controller
    //generate token for users
    public String generateToken(UserDetails userDetails){
        Map<String, String> claims = new HashMap<>();
        claims.put("iss", "http://secure.genuinecoder.com");//claim to be added to payload in the iss or issuer section
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername()) //user the token is being created for
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
                .signWith(generateKey())
                .compact(); //converts the token into a JSon format
    }

    //convert key into a SecretKey object to sign token
    private SecretKey generateKey(){
        byte[] decodeKey = Base64.getDecoder().decode(SECRET); //decode the key
        return Keys.hmacShaKeyFor(decodeKey); //convert decoded key into secret key
    }

    //extract username from validated token
    public String extractUsername(String jwt) {
        Claims claims = getClaims(jwt);
        return claims.getSubject();//get the username
    }

    private Claims getClaims(String jwt) {
        return Jwts.parser()//user .builder() to generate token, but parse to extract from token
                            .verifyWith(generateKey())
                            .build()
                            .parseSignedClaims(jwt)
                            .getPayload();
    }

    public boolean isTokenValid(String jwt) {
        Claims claims = getClaims(jwt);
        return claims.getExpiration().after(Date.from(Instant.now()));//expiration date in the future
    }
}
