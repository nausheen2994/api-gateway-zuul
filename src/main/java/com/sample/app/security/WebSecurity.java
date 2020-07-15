package com.sample.app.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	Environment env;

	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.headers().frameOptions().disable();
		http.authorizeRequests().antMatchers(HttpMethod.POST, env.getProperty("api.registration.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, env.getProperty("api.login.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, env.getProperty("api.h2.console")).permitAll().anyRequest()
				.authenticated().and().addFilter(new Authfilter(authenticationManager(), env));
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

}
