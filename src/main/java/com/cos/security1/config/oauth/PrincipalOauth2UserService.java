package com.cos.security1.config.oauth;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
	// loginForm.html(로그인 시도) -> 구글에서 로그인 페이지 전송 -> SecurityConfig에서 .loginPage("/loginForm") 받아줌 -> 
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;
	
	
	// 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
	// 함수 종료 시@AuthenticationPrincipal 어노테이션이 만들어진다. 
	// 결국 얘를 오버라이딩 한 이유는 1. PrincipalDetails로 묶기 위함, 2. OAuth로 들어왔을 때 강제 회원가입 진행을 위함
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("userRequest : "+userRequest); // userRequest : org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest@2727096
		
		System.out.println("userRequest : "+userRequest.getClientRegistration());	// registrationId로 어떤 OAuth로 로그인 했는지 확인 가능.
		System.out.println("userRequest : "+userRequest.getAccessToken().getTokenValue());
		// 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
		// 얘네가 userRequest 정보 ->loadUser함수 -> 회원프로필(구글로부터)
		//System.out.println("userRequest : "+super.loadUser(userRequest).getAttributes());
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		System.out.println("userRequest : "+oauth2User.getAttributes());
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
			
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
			
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo( (Map<String, Object>) oauth2User.getAttributes().get("response") );
			
		}else {
			System.out.println("우리는 구글과 페이스북만 지원해요!");
		}
		
		// User 객체에 삽입 준비
		String provider = oAuth2UserInfo.getProvider(); // google
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		
		// 자동 회원가입 실시
		if(userEntity == null) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			
			userRepository.save(userEntity);
			
		}else {
			System.out.println("로그인을 이미 한적 있습니다. 당신은 자동회원가입이 되어 있습니다.");
		}

		// PrincipalDetails에서 OAuth2User를 상속하고 있기 때문에 
		// PrincipalDetails를 반환하면 결국 OAuth2User 관련 정보를 반환하는 것이다.
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
