package com.joeun.server.security.jwt.provider;

import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.joeun.server.mapper.UserMapper;
import com.joeun.server.prop.JwtProps;
import com.joeun.server.security.jwt.constants.JwtConstants;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT토큰 관련 기능을 제공해주는 클래스
 * 1. 토큰 생성
 * 2. 토큰 해석
 * 3. 토큰 유효성 검사
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Autowired
    private JwtProps jwtProps; //시크릿키를 가져오는 용도

    @Autowired
    private UserMapper userMapper;

    /*
     * 👩‍💼➡️🔐 토큰 생성
     */
    public String createToken(int userNo, String userId, List<String> roles) {
        byte[] signingKey = getSigningKey();

        // JWT 토큰 생성
        String jwt = Jwts.builder()
                .signWith(getShaKey(), Jwts.SIG.HS512) // 서명에 사용할 키와 알고리즘 설정
                // .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE) // deprecated (version:
                // before 1.0)
                .header() // update (version : after 1.0)
                .add("typ", JwtConstants.TOKEN_TYPE) // 헤더 설정 (JWT)
                .and()

                .expiration(new Date(System.currentTimeMillis() + 864000000)) // 토큰 만료 시간 설정 (10일)
                .claim("uno", "" + userNo) // 클레임 설정: 사용자 번호
                .claim("uid", userId) // 클레임 설정: 사용자 아이디
                .claim("rol", roles) // 클레임 설정: 권한
                .compact();

        log.info("jwt : " + jwt);

        return jwt;
    }

    // secretKey ➡️ signingKey
    private byte[] getSigningKey() {
        return jwtProps.getSecretKey().getBytes();
    }

    // secretKey ➡️ (HMAC-SHA algorithms) ➡️ signingKey
    private SecretKey getShaKey() {
        return Keys.hmacShaKeyFor(getSigningKey());
    }

















}
