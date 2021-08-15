package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping({"","/"})
	public String index() {
		// 머스테치 기본폴더 : src/main/resources/
		// view resolver 설정 : templates (prefix), .mustache (suffix) 생략가능!!
		return "index";	// src/main/resources/templates/index.mustache
	}
	
	@GetMapping("/user")
	public @ResponseBody  String user() {
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
