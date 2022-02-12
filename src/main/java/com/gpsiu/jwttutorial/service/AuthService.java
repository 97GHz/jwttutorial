package com.gpsiu.jwttutorial.service;

import com.gpsiu.jwttutorial.config.TokenProvider;
import com.gpsiu.jwttutorial.dto.TokenDto;
import com.gpsiu.jwttutorial.dto.User;
import com.gpsiu.jwttutorial.exception.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public TokenDto authorize(String email, String password) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(email, password);

        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String authorities = getAuthorities(authentication);

        return tokenProvider.createToken(authentication.getName(), authorities);
    }

    public TokenDto reissue(String requestAccessToken, String requestRefreshToken){
        if(!tokenProvider.validateToken(requestRefreshToken)) {
            throw new UnauthorizedException("유효하지 않은 Refresh Token");
        }
        Authentication authentication = tokenProvider.getAuthentication(requestAccessToken);

        User principal = (User) authentication.getPrincipal();

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String authorities = getAuthorities(authentication);

        return tokenProvider.createToken(principal.getEmail(), authorities);
    }

    private String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }
}
