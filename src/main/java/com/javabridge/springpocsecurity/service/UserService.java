package com.javabridge.springpocsecurity.service;

import com.javabridge.springpocsecurity.configuration.SecurityConfiguration;
import com.javabridge.springpocsecurity.dto.CreateUserDto;
import com.javabridge.springpocsecurity.dto.LoginUserDto;
import com.javabridge.springpocsecurity.dto.RecoveryJwtTokenDto;
import com.javabridge.springpocsecurity.entities.Role;
import com.javabridge.springpocsecurity.entities.User;
import com.javabridge.springpocsecurity.impl.UserDetailsImpl;
import com.javabridge.springpocsecurity.repository.UserRepository;
import com.javabridge.springpocsecurity.security.JwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityConfiguration securityConfiguration;

    public RecoveryJwtTokenDto authenticateUser(LoginUserDto loginUserDto) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginUserDto.email(), loginUserDto.password());

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return new RecoveryJwtTokenDto(jwtTokenService.generateToken(userDetails));
    }

    public void createUser(CreateUserDto createUserDto) {

        User newUser = User.builder()
                .email(createUserDto.email())
                .password(securityConfiguration.passwordEncoder().encode(createUserDto.password()))
                .roles(List.of(Role.builder().name(createUserDto.role()).build()))
                .build();

        userRepository.save(newUser);
    }
}
