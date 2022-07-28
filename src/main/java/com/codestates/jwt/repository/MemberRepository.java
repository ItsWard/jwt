package com.codestates.jwt.repository;

import com.codestates.jwt.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    public Member findByUsername(String member);

}
