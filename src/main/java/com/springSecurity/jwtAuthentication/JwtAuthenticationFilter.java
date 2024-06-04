package com.springSecurity.jwtAuthentication;

import com.springSecurity.jwtAuthentication.model.MyUserDetailService;
import com.springSecurity.jwtAuthentication.webtoken.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//this class is to validate the token upon user's further requests using the
//authorization's header (Bearer ......)
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //OncePerRequestFilter will be executed once for every requests

    @Autowired
    private JwtService jwtService;
    @Autowired
    private MyUserDetailService myUserDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);//don't do anything, continue
            return; //continue
        }
        //get the token or jwt value removing the first 7 characters (Bearer )
        String jwt = authHeader.substring(7); // 7 means Bearer + space
        String username = jwtService.extractUsername(jwt);

        //if the user is not already logged in, manually give him a logged-in context so that
        //he is not authenticated over and over. If authentication is null, this means the user
        //has not been authenticated, so we load him and authenticate him so that we can give him a logged-in context
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = myUserDetailService.loadUserByUsername(username);

            //manually create username and password once token is validated
            if(userDetails != null && jwtService.isTokenValid(jwt)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username, userDetails.getPassword(), userDetails.getAuthorities()
                );
                //to keep track of who is logged into the system
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //mark the context as logged-in
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
