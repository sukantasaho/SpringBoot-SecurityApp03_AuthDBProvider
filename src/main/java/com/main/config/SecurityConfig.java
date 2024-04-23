package com.main.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private DataSource ds;
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		  //configure jdbc as authntication provider
		auth.jdbcAuthentication().dataSource(ds).passwordEncoder(new BCryptPasswordEncoder())
		.usersByUsernameQuery("SELECT UNAME, PWD, STATUS FROM USERS WHERE UNAME=?")
		.authoritiesByUsernameQuery("SELECT ROLE, UNAME FROM USER_ROLES WHERE UNAME=?");
	}
	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		//place the authentication and authorization logics for the request url
		http.authorizeRequests().antMatchers("/").permitAll()//no Authentication and Authorization 
		.antMatchers("/offers").authenticated()//only Authentication
		.antMatchers("/showBalance").hasAnyAuthority("customer","manager")
		.antMatchers("/approveLoan").hasAuthority("manager")
		.anyRequest().authenticated()
		//.and().httpBasic()
		.and().formLogin()
		//.and().rememberMe()
	    .and().logout()
		.and().exceptionHandling().accessDeniedPage("/denied")
		.and().sessionManagement().maximumSessions(10).maxSessionsPreventsLogin(true);
		 
	}
	
}
