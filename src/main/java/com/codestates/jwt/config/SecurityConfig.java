package com.codestates.jwt.config;

import com.codestates.jwt.filter.FirstFilter;
import com.codestates.jwt.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CorsFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.headers().frameOptions().disable(); // h2 <- frame Element 이용, disable 하지않으면,

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new CustomDsl())
        ;
        http
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
        ;



        return http.build();
    }

    public class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder
                    .addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
        }
    }

}
