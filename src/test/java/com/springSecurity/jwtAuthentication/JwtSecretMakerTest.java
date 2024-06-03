package com.springSecurity.jwtAuthentication;

import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;


public class JwtSecretMakerTest {
    //generating secret key
    @Test
    public void generateSecretKey(){
        SecretKey key = Jwts.SIG.HS512.key().build(); //create the secret key
        String encodedKey = DatatypeConverter.printHexBinary(key.getEncoded()); //convert the key into a string value
        System.out.printf("\nKey = [%s]\n",encodedKey); //print the key so that we can copy it
    }
}
