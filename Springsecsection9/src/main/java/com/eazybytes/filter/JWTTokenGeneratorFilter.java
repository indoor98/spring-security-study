package com.eazybytes.filter;

import com.eazybytes.constants.SecurityConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 해당 필터는 BasicAuthenticationFilter 다음에 올 것이다. 따라서 이미 유저 정보는 인증 되었으므로
        // 인증된 객체를 불러오기위해 다음과 같이 작성하였다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(null != authentication) {
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder().issuer("Eazy Bank").subject("JWT Token") // issuer : 해당 토큰 발행 주체, subject 주제
                    .claim("username", authentication.getName()) // claim: payload 내용
                    .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                    .issuedAt(new Date()) // 토큰 발행 날짜값
                    .expiration(new Date((new Date()).getTime()+3000)) // 토큰 만료일 , 단위는 밀리초
                    .signWith(key).compact(); // key값을 가지고 서명 -> Signature
            response.setHeader(SecurityConstants.JWT_HEADER, jwt);
        }
        filterChain.doFilter(request, response);
    }


    // 이 메소드에 조건을 제공한다면 필터를 거치지 않는다.
    // 즉 해당 필터는 로그인 요청 외에는 무시해야 한다는 뜻이다.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/user");
    }

    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }
}
