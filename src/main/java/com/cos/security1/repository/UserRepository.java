package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있다
// @Repository라는 어노테이션이 없어도 IoC되요. 이유는 JpaRepository를 상속했기 때문에
public interface UserRepository extends JpaRepository<User, Integer> {
	
	
	// findBy규칙 -> Username 문법 자동변환됨
	// select * from user where username = 1?;
	public User findByUsername(String username);	// Jpa Query method
	
}
