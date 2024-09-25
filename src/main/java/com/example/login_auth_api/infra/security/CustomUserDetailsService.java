package com.example.login_auth_api.infra.security;

import com.example.login_auth_api.domain.user.User;
import com.example.login_auth_api.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userFound = userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("Username not found."));
        return new org.springframework.security.core.userdetails.User(
                userFound.getEmail(), userFound.getPassword(), new ArrayList<>());
    }
}
