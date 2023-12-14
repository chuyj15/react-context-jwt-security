package com.joeun.server.prop;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties("com.joeun.server") //applicaion.properties의 하위 속성 경로 지정
public class JwtProps {
    //시크릿키 : jwt 시그니처 암호화를 위한 정보
    private String secretKey;
    //이걸 나중에 필터에서 활용해줄 겁니다. 
}
