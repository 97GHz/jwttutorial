package com.gpsiu.jwttutorial.config;

import com.gpsiu.jwttutorial.dto.TokenDto;
import com.gpsiu.jwttutorial.dto.User;
import com.gpsiu.jwttutorial.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Value;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "role";

    private final String secret;
    private final Long accessTokenValidityInMilliseconds;
    private final Long refreshTokenValidityInMilliseconds;

    private Key key;

    private final UserRepository userRepository;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity-in-seconds") Long accessTokenValidityInMilliseconds,
            @Value("${jwt.refresh-token-validity-in-seconds") Long refreshTokenValidityInMilliseconds,
            UserRepository userRepository) {
        this.secret = secret;
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMilliseconds * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMilliseconds * 1000;
        this.userRepository = userRepository;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto createToken(String email, String authorities) {
        Long now = (new Date()).getTime();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("???????????? ???????????? ???????????? ????????????."));

        String accessToken = Jwts.builder()
                .claim("email", user.getEmail())
                .claim("nickname", user.getNickname())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(new Date(now + accessTokenValidityInMilliseconds))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = Jwts.builder()
                .claim("email", user.getEmail())
                .claim("nickname", user.getNickname())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(new Date(now + refreshTokenValidityInMilliseconds))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return new TokenDto(accessToken, refreshToken);
    }

    // ????????? ???????????? ?????????
    // JWT Filter?????? ????????????, ???????????? ??????????????? ????????????, Authentication ????????? ????????? SecurityContext??? ??????
    // ?????? Controller?????? @AuthenticalPrincipal??? SecurityContext??? ?????? ????????? ????????? Email?????? ??????
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(claims.get("email"), null, authorities);
    }

    private Claims getClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            // ????????? JWT ??????
        } catch (ExpiredJwtException e) {
            // ????????? JWT ??????
        } catch (UnsupportedJwtException e) {
            // ???????????? ?????? JWT ??????
        } catch (IllegalArgumentException e) {
            // ????????? ??????
        }
        return false;
    }
}
