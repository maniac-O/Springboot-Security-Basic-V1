package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	
	// 세션에 들어간 정보를 받는 방법은 크게 2가지다.
	// 첫번째로 Authentication 정보에 UserDetails를 다운캐스팅해서 받는 방법,
	// 두번째로 @AuthenticationPrincipal 어노테이션을 사용한 PrincipalDetails 사용 
	@GetMapping("/test/login")
	
	// 2. @AuthenticationPrincipal 어노테이션을 사용하면 세션 정보를 가져올 수 있다.
	// 해당 어노테이션은 UserDetails 타입을 가지고 있는데, PrincipalDetails가 해당 타입을 implementation 하고 있기 때문에 바꿔 줄 수 있다.
	public @ResponseBody String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) { // DI (의존성 주입)
		
		// 1. 의존성 주입 시 authentication 객체 안에 Principal이 있고
		// 리턴 타입이 Object 이기 때문에 다운 캐스팅해서 getUser를 호출하면 된다.
		// 하지만 만약 구글 로그인을 한다면 ClassCastException 오류가 나는데, 
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : " + principalDetails.getUser());
		
		System.out.println("userDetails : "+ userDetails.getUser());
		return "세션 정보 확인하기";
	}

	// ClassCastException 오류가 난 구글 로그인의 처리 방법은 다음과 같다.
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		
		// 이 정보는 PrincipalOauth2UserService 에 super.loadUser(userRequest).getAttributes() 정보이다.
		// OAuth로 로그인 하면 authentication에 OAuth 객체로 들어가 있기 때문에 이렇게 받아야한다.
		
		// 이렇게 일반 로그인 / 구글 로그인으로 나눠져있기 때문에 처리해줄때 어떻게 처리해줘야 하냐?
		// PrincipalDetails와 OAuth2User를 상속하는 클래스 하나를 만들어서 넣어주면 된다.
		// 근데 PrincipalDetails가 Authentication에 들어가는데, 타이밍은 PrincipalDetailsService에서 loadUserByUsername을 호출할 때 들어간다. 
		// loadUserByUsername이 종료되면서, PrincipalDetails(userEntity)가 리턴 되는데, (Authentication안에 PrincipalDeatils 객체가 들어간 것이다.)
		System.out.println("authentication : " + oauth2User.getAttributes());
		System.out.println("oauth2User : "+ oauth.getAttributes());
		
		return "세션 정보 확인하기";
	}
	
	@GetMapping({"","/"})
	public String index() {
		// 머스테치 기본폴더 : src/main/resources/
		// view resolver 설정 : templates (prefix), .mustache (suffix) 생략가능!!
		return "index";	// src/main/resources/templates/index.mustache
	}
	
	// OAuth 로그인을 해도 PrincipalDetails
	// 일반 로그인을 해도 PrincipalDetails
	// @AuthenticationPrincipal 어노테이션은 언제 활성화 되냐?
	// PrincipalOauth2UserService를 만들지 않아도 기본적으로 loadUser와 loadUserByUsername이 발동해 대신 로그인 해 주는데,
	// 우리가 할려는 건 PrincipalDetails를 둘다 리턴 해주는 것이다. 
	// PrinciaplOauth2UserSerivce에서 loadUser가 리턴되면 그 때 Authentication에 저장된다. (당연히 PrincipalDetailsService 에서 loadUserByUsername이 리턴될때도 Authentication에 객체가 저장된다.)
	@GetMapping("/user")
	public @ResponseBody  String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails : " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody  String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody  String manager() {
		return "manager";
	}
	
	// 스프링시큐리티 해당주소를 낚아채서 로그인 불가 - SecurityConfig 파일 생성 후 작동안함.
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		
		userRepository.save(user); // 회원가입 잘되지만 하면 안된다. : 비밀번호가 고냥 평문으로 저장되기 때문에 시큐리티로 로그인을 할 수 없다. => 패스워드가 암호화가 되어있지 않다.
		
		return "redirect:/loginForm";
	}
	
	// @Secured / @PreAuthorize 는 SecurityConfig에서 => @EnableGlobalMethodSecurity(securedEnabled = true) 어노테이션을 활성화 시켜줘야 한다.
	
	//@Secured("ROLE_ADMIN")	// 특정 메소드에 간단하게 접근 제한하는 속성
	@PreAuthorize("hasRole('ROLE_MANAGER')")	// 메소드가 실행되기 직전에 실행된다.
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}
	
}
