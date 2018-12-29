package com.sid.secure.oauth2;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
	return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
	http.csrf().disable().httpBasic().and().exceptionHandling()
		.authenticationEntryPoint(
			(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
		.and().authorizeRequests().antMatchers("/oauth/token").permitAll().anyRequest().authenticated()
		.antMatchers("/**").authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	auth.inMemoryAuthentication().withUser("reader").password(passwordEncoder().encode("reader"))
		.authorities("FOO_READ").and().withUser("writer").password(passwordEncoder().encode("writer"))
		.authorities("FOO_READ", "FOO_WRITE");
    }
}
