package com.springSecurity.jwtAuthentication;

import com.springSecurity.jwtAuthentication.model.MyUserDetailService;
import com.springSecurity.jwtAuthentication.webtoken.JwtService;
import com.springSecurity.jwtAuthentication.webtoken.LoginForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

//First class created followed by SecurityConfiguration
@Controller //tell spring boot that this is a controller class
public class ContentController {
    @Autowired
    private AuthenticationManager authenticationManager;//to authenticate by username and password without any logic separately
    @Autowired
    private JwtService jwtService;
    @Autowired
    private MyUserDetailService myUserDetailService;


    @GetMapping("/home")
    public String handleWelcome(){
        return "Welcome to home!";
    }

    @GetMapping("/admin/home")
    public String handleAdminHome(){
        return "Welcome to ADMIN home!";
    }

    @GetMapping("/user/home")
    public String handleUserHome(){
        return "Welcome to USER home!";
    }

    @PostMapping("/authenticate")
    public String authenticationAndGetToken(@RequestBody LoginForm loginForm){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginForm.username(), loginForm.password()
        ));
        if(authentication.isAuthenticated()){
            return jwtService.generateToken(myUserDetailService.loadUserByUsername(loginForm.username()));
        } else{
            throw new UsernameNotFoundException("Invalid Credential.");
        }
    }
}
