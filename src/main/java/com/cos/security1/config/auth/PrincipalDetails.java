package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.security1.model.User;

import lombok.Data;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료가 되면 시큐리티 session을 만들어줍니다. (Security ContextHolder 에 세션정보를 저장시킨다.)
// 오브젝트 => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 됨.
// User오브젝트 타입 => UserDetails 타입 객체

// Security Session 영역에 정보를 저장하는데  => Authentication => UserDetails(PrincipalDetails)


// 2021-08-19:
// PrincipalDetails를 만든대는 2가지 이유가 있다.
// 첫번째로는 시큐리티가 들고있는 세션정보에는 Authentication 객체를 넣어야 한다.
// Authentication 객체에는 OAuth2User / UserDetails 타입 둘중 하나의 타입을 넣을 수 있다.

// 하지만 회원가입 시 User Object를 사용, 하지만 OAuth2User와 UserDetails는 User Object를 모른다.
// PrincipalDetails를 만들어서 User Object를 품어야 한다. 그리고 Authentication에는 PrincipalDetails를 넣어준다.
// 세션에 접근하면 User Object를 들고있는 PrincipalDetails를 넣어놨기 때문에 가져올 수 있다.

// PrincipalDeatils 에서 OAuth2User를 받으면 자식 입장으로 묶어버릴 수 있다.
// 
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
	
	private User user;
	private Map<String,Object> attributes;
	
	// 일반 로그인 생성자
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// OAuth 로그인 생성자
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}
	
	// 해당 User의 권한을 리턴하는 곳!
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				// TODO Auto-generated method stub
				return user.getRole();
			}
		});
		// TODO Auto-generated method stub
		return collect;
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		
		// 우리 사이트!! 1년동안 회원이 로그인을 안하면! 휴먼 계정으로 전환하기로 함
		// User 테이블에 최종 로그인 시간을 추가시켜주고
		// 현재시간 - 로그인시간 => 1년을 초과하면 return false
		
		// TODO Auto-generated method stub
		return true;
	}

	
	// 여기서부터 OAuth2User
	@Override
	public Map<String, Object> getAttributes() {
		// TODO Auto-generated method stub
		return attributes;
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}
	
	
}
