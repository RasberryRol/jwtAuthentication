package com.springSecurity.jwtAuthentication.webtoken;

//this class is to get the username and password
public record LoginForm (String username, String password){
    //a record automatically provides all setters and getters like a normal class
}
