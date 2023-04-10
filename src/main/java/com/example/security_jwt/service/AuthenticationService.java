package com.example.security_jwt.service;

import com.example.security_jwt.Configuration.JwtService;
import com.example.security_jwt.Repository.UserRepository;
import com.example.security_jwt.User.Role;
import com.example.security_jwt.User.User;
import com.example.security_jwt.auth.AuthenticationRequest;
import com.example.security_jwt.auth.AuthenticationResponse;
import com.example.security_jwt.auth.RegisterRequest;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;


    public AuthenticationResponse register(RegisterRequest request) {
        var user= User.builder()
                .email(request.getEmail())
                .fistName(request.getFirstName())
                .lastName(request.getLastName())
                .password(encoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
         repository.save(user);
         var jwtToken= jwtService.generateToken(user);
         return AuthenticationResponse.builder()
                 .token(jwtToken)
                 .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
          authenticationManager.authenticate(
                  new UsernamePasswordAuthenticationToken(
                          request.getEmail(),
                          request.getPassword()));

          var user= repository.findByEmail(request.getEmail())
                  .orElseThrow(EntityNotFoundException::new);

        var jwtToken= jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
