package com.springSecurity.jwtAuthentication;

import com.springSecurity.jwtAuthentication.model.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration //tell spring that this is a configuration class
@EnableWebSecurity //to enable spring security
public class SecurityConfiguration {
    @Autowired
    private MyUserDetailService userDetailService;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    //this Bean provides a default security filterChain for the login page.
    //we use httpSecurity to customize it and indicate which end-points have
    //which authorization
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)
        throws Exception {
        return httpSecurity
                //by default, csrf blocks all Post requests. So when trying to post to the database
                //csrf will block the request unless it is disabled as shown below
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(registry->{
            registry.requestMatchers("/home", "/register/**", "/authenticate").permitAll();
            registry.requestMatchers("/admin/**").hasRole("ADMIN");
            registry.requestMatchers("/user/**").hasRole("USER");
            registry.anyRequest().authenticated(); //any request not mentioned above needs to
                                                    //be authenticated
        })
                //to make the login page accessible to anyone
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll) //this is a reference to (formLogin -> formLogin.permitAll())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)//this is to load the jwtAuth... filter before the UsernamePass... filter
                .build();  //NEXT, WE CREATE THE IN-MEMORY USERS BELOW
    }

//a Bean is an instantiation of java core object such JpaRepository instanced as:
    //public.error void JpaRepository jpaRepository(){}
//    @Bean
//    public.error UserDetailsService userDetailsService(){
//        UserDetails normalUser = User.builder()
//                .username("gc")
//                .password("$2a$12$v8/r9pbeX60VJs97e.2ZqOrlCzSTWe3Iys/WBE4V9CTz3q0GOHeoO")
//                            //use an online generator to generate to encoded password for "1234".
//                            //password is encoded because others may have access to the code
//                            //to encode, we indicate what kind of encoding technique we are using below
//                .roles("USER")
//        .build();
//
//        UserDetails adminUser = User.builder()
//                .username("admin")
//                .password("$2a$12$hl8LoubF4s/ARJtOMBTkMOPqIOXNC91qV9TnKto4ZsQ6.CYIH4LJu")
//                //use an online generator to generate to encoded password for "6261".
//                //password is encoded because others may have access to the code
//                //to encode, we indicate what kind of encoding technique we are using below
//                .roles("ADMIN", "USER")
//                .build();
//
//        //this is to provide the above info to the UserDetailsService
//        return new InMemoryUserDetailsManager(normalUser, adminUser);
//    }

    //this is to link MyUserDetailService to SecurityConfiguration
    @Bean
    public UserDetailsService userDetailsService(){
        return userDetailService;
    }

    //this is to tell the UserDetailsService what king of authentication provider we are using
    @Bean
    public AuthenticationProvider authenticationProvider(){
        //used when loading data from the database
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailService);
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(authenticationProvider());
    }


    //this Bean is to indicate what encoding technique is being used for the password
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //NEXT WE LOAD DATA FROM DATABASE BY ESTABLISHING CONNECTION THEN CREATE SCHEMA CLASS IN MODEL
}
