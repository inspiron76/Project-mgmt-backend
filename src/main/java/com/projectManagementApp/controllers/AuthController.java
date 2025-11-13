package com.projectManagementApp.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.projectManagementApp.config.JwtHelper;
import com.projectManagementApp.entities.Role;
import com.projectManagementApp.entities.User;
import com.projectManagementApp.globalException.EmailAllreadyExist;
import com.projectManagementApp.payloads.AuthResponse;
import com.projectManagementApp.payloads.Credentials;
import com.projectManagementApp.repositories.RoleRepository;
import com.projectManagementApp.repositories.UserRepository;
import com.projectManagementApp.security.service.UserDetailsImpl;
import com.projectManagementApp.services.SubscriptionService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private JwtHelper jwtHelper;
    
    
    @Autowired
    private SubscriptionService subscriptionService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody Credentials credentials) {
       try {
            Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(credentials.getEmail(), credentials.getPassword())
            );
            
            if (authentication.isAuthenticated()) {
                // Try to find user by email first, then by username
                Optional<User> userOptional = this.userRepository.findByEmail(credentials.getEmail());
                if (userOptional.isEmpty()) {
                    userOptional = this.userRepository.findByUsername(credentials.getEmail());
                }
                
                if (userOptional.isEmpty()) {
                    return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
                }
                
                User user = userOptional.get();
                GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().getRoleName());
                UserDetailsImpl userDetailsImpl = new UserDetailsImpl(
                    user.getUserId(), 
                    user.getUsername(), 
                    user.getEmail(), // Use actual email instead of credentials.getUsername()
                    user.getPassword(), 
                    List.of(authority)
                );
                
                String token = jwtHelper.generateToken(userDetailsImpl);
                AuthResponse authResponse = new AuthResponse();
                authResponse.setExpirationTime(jwtHelper.getExpiration(token));
                authResponse.setJwt(token);
                authResponse.setMessage("Login Successfully");
                
                return new ResponseEntity<>(authResponse, HttpStatus.OK);
            }
        } catch (BadCredentialsException e) {
            AuthResponse authResponse = new AuthResponse();
            authResponse.setMessage("Invalid username or password");
            return new ResponseEntity<>(authResponse, HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            AuthResponse authResponse = new AuthResponse();
            authResponse.setMessage("Authentication failed");
            return new ResponseEntity<>(authResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        
        // This should never be reached, but just in case
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
    
    @PostMapping("/signup") // Added missing @PostMapping annotation
    @Valid // Added validation annotation
    private ResponseEntity<AuthResponse> signUp(@RequestBody @Valid User user) throws EmailAllreadyExist {
        // Check if email already exists
        Optional<User> isExist = this.userRepository.findByEmail(user.getEmail());
        
        if (isExist.isPresent()) {
            throw new EmailAllreadyExist("Email is already associated to another account");
        }
        
        // Check if username already exists (optional but recommended)
        Optional<User> usernameExists = this.userRepository.findByUsername(user.getUsername());
        if (usernameExists.isPresent()) {
            throw new EmailAllreadyExist("Username is already taken");
        }
        
        try {
            // Create new user object
            User createdUser = new User();
            createdUser.setPassword(passwordEncoder.encode(user.getPassword()));
            createdUser.setUsername(user.getUsername());
            createdUser.setEmail(user.getEmail()); // Don't forget to set email
            
            // Set default role (assuming you have a default role like "USER")
            Optional<Role> defaultRole = roleRepository.findByRoleName("ROLE_USER"); // Adjust role name as needed
            if (defaultRole.isPresent()) {
                createdUser.setRole(defaultRole.get());
            } else {
                // Handle case where default role doesn't exist
                throw new RuntimeException("Default role not found");
            }
            
            // Save the user
            User savedUser = this.userRepository.save(createdUser);
            
            subscriptionService.createSubscripton(savedUser);
            
            // Generate JWT token similar to login
            GrantedAuthority authority = new SimpleGrantedAuthority(savedUser.getRole().getRoleName());
            UserDetailsImpl userDetailsImpl = new UserDetailsImpl(
                savedUser.getUserId(), 
                savedUser.getUsername(), 
                savedUser.getEmail(), 
                savedUser.getPassword(), 
                List.of(authority)
            );
            
            String jwt = jwtHelper.generateToken(userDetailsImpl);
            
            // Create authentication response
            AuthResponse authResponse = new AuthResponse();
            authResponse.setExpirationTime(jwtHelper.getExpiration(jwt));
            authResponse.setJwt(jwt);
            authResponse.setMessage("User registered successfully");
            
            
            return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
            
        } catch (Exception e) {
            // Handle any other exceptions
            AuthResponse authResponse = new AuthResponse();
            authResponse.setMessage("Registration failed: " + e.getMessage());
            return new ResponseEntity<>(authResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
   

}