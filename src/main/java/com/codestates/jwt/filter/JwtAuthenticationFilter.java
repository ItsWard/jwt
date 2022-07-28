package com.codestates.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codestates.jwt.model.Member;
import com.codestates.jwt.oauth.PrincipalDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println("input = " + input);
//            }
            ObjectMapper om = new ObjectMapper();
            Member member = om.readValue(request.getInputStream(), Member.class); //입력 데이터를 json 방식으로 변환, MemberClass DTO

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos jwt token")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 1000 * 10))) //현재시간 ~ 10분?
                .withClaim("id", principalDetails.getMember().getId())
                .withClaim("username", principalDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512("cos_jwt_token"));
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
