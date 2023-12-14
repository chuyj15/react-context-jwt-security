package com.joeun.server.security.jwt.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
/*
 * 🎊요약
 * 클라이언트 ->로그인 경로 : filter -> server
 * ✨username, password 인증 시도 : attemptAuthentication 메소드
 * ✨인증 성공하면 : successfulAuthentication 메소드. ]
 * ===> 이 안에서 🧨JWT 생성, 🧨response>header>authorization 안에 jwt 담는 작업
 * ✨인증 실패 시 : attemptAuthentication 메소드
 * ===> 이 안에서 🧨response>status>401 담아주기
 */
//로그인(두번째 필터)
//스프링시큐리티와의 연결을 위해 상속을 받습니다. 
//그 중 2개의 메소드를 오버라이딩 해줍니다. 
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // @Autowired
    // private AuthenticationManager authenticationManager; //이렇게 할수있다고 생각하지만 불가능합니다... 왜??
    private final AuthenticationManager authenticationManager;
    
    //생성자에다가 AuthenticationManager 를 넣어서 생성해줄 겁니다. 

    //생성자 (추가로 토큰을 생성하는 것도 매개변수에 넣어줄 예정입니다. )
    public JwtAuthenticationFilter (AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        //필터  url 경로 설정 : /login
        setFilterProcessesUrl(("/login"));
    }

    // 인증 시도 메소드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        // request에서 파라미터를 꺼냅니다.
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("username : "+username);
        log.info("password : "+password);
        //사용자 인증정보 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        //사용자 인증 (로그인)
        //authenticationManager을 빈으로 등록해주는 작업은 SecurityConfig.java에서 해줄거에요.
        authentication = authenticationManager.authenticate(authentication); //UserDeatilsService 와 PasswordEncoder 두 설정이 이 메소드가 호출되었을 때 타게 됩니다. 
        log.info("인증 여부 : "+authentication.isAuthenticated());
        //인증 실패 로직 (usernme, password 불일치)
        if ( !authentication.isAuthenticated()){
            log.info("인증 실패 : 아이디 또는 비밀번호가 일치하지 않습니다. ");
            response.setStatus(401); //UNAUTHORIZED (인증 실패)
        }
        return authentication;
    }

    // 인증 성공 시 실행될 메소드
    //authentication.isAuthenticated() 가 true면 이 메소드가 실행되는 겁니다. 
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }

}
