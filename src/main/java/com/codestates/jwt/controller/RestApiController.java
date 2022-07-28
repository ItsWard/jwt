package com.codestates.jwt.controller;

import com.codestates.jwt.model.Member;
import com.codestates.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {

        return "<h1>home</h1>";
    }
    @PostMapping("/token")
    public String token() {

        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody Member member) {

        member.setPassword(bCryptPasswordEncoder.encode(member.getPassword()));
        member.setRoles("ROLE_USER");
        memberRepository.save(member);
        return "회원 가입 완료";
    }



}
