package com.joeun.server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import com.joeun.server.dto.UserAuth;
import com.joeun.server.dto.Users;
import com.joeun.server.mapper.UserMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserServiceImpl implements UserService {
    // 스프링시큐리티에 미리정의된 passwordEncoder 객체 가져오기. 비밀번호암호화작업을 위해
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private AuthenticationManager authenticationManager ;

    // 회원가입 1. 비밀번호 암호화 2. 회원등록 3. 권한등록
    @Override
    public int insert(Users user) throws Exception {
        String userPw = user.getUserPw();
        String encodedPw = passwordEncoder.encode(userPw);
        user.setUserPw(encodedPw);
        int result = userMapper.insert(user);
        if (result > 0){
            UserAuth userAuth = new UserAuth();
            userAuth.setUserId(user.getUserId());
            userAuth.setAuth("ROLE_USER");
            result = userMapper.insertAuth(userAuth);
        }
        return result;
    }

    @Override
    public Users select(int userNo) throws Exception {
        return userMapper.select(userNo);
    }

    //로그인
    @Override
    public void login(Users user, HttpServletRequest request) throws Exception {
        String username = user.getUserId();
        String password = user.getUserPw();
        log.info("username : "+ username);
        log.info("password : "+ password); //여기선 비밀번호암호화 안하는 이유: 시큐리티컨피그에서 비밀번호 암호화 설정을 해줄거기 때문에. 
        //디비에 넣는 건 시큐리티를 거치지 않기 때문에 직접 비밀번호 암호화를 해준다. 
        //여기서 바로 로그인을 하고 싶다면? 
        //스프링시큐리티의 AuthenticationManager 객체(인증을 관리함)가  필요하다. 
        //아이디, 패스워드 인증 토큰 생성해서 인증요청을 함. 
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        //토큰에 요청정보 등록 - request를 넣는 이유? HttpServletRequest 자체는 요청정보를 들고있는 객체이기에 변조할 수 없어서 ,,즉 우리 클라이언트에서 온 정보임을 확인하는 용도입니다.
        //
        token.setDetails( new WebAuthenticationDetails(request) );
        //토큰을 이용하여 인증 요청 - 로그인
        //authenticate(token); 이 메소드가 db에 있는 정보와 대조해봅니다. (jdbc방식으로 하냐 뭐로 하냐는 securityConfig에서 설정해줍니다. )
        Authentication authentication = authenticationManager.authenticate(token);
        log.info("인증 여부 : "+authentication.isAuthenticated());
        User authUser = (User) authentication.getPrincipal(); // 이건 스프링시큐리티의 유저객체입니다. 
        log.info("인증된 사용자 : "+authUser.getUsername());
        //시큐리티 컨텍스트에 인증된 사용자 등록 - 여기에 담아줘야 매번 인증된 사용자정보를 여기서 가져올 수 있습니다. 
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //이렇게 하면 controller에서 인증된 객체를 불러올 수 있습니다. 
    }

    @Override
    public int update(Users user) throws Exception {
        //다른 건 그대로 업데이트. 비밀번호만 암호화
        String userPw = user.getUserPw();
        String encodedPw = passwordEncoder.encode(userPw);
        user.setUserPw(encodedPw);
        int result = userMapper.update(user);
        return result;
    }

    @Override
    public int delete(String userId) throws Exception {
        return userMapper.delete(userId);
    }


}
