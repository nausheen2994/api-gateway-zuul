package com.sample.app.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class Authfilter  extends BasicAuthenticationFilter{
	
	private Environment env;

	public Authfilter(AuthenticationManager authManager,Environment env) {
		super(authManager);
		this.env=env;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {
		
		String authorization=request.getHeader(env.getProperty("authorization.token.header.name"));
		if(authorization==null || !authorization.startsWith(env.getProperty("authorization.token.header.name.prefix"))) {
			chain.doFilter(request, response);
			return;
		}
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=getAuthorization(request);
		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
		chain.doFilter(request, response);
		
	}

	private UsernamePasswordAuthenticationToken getAuthorization(HttpServletRequest request) {
		String authorization=request.getHeader(env.getProperty("authorization.token.header.name"));
		
		if(authorization==null)
			return null;
		String token=authorization.replace(env.getProperty("authorization.token.header.name.prefix"),"");
		
		
		
		String userId=Jwts.parser().setSigningKey(env.getProperty("token.secret")).parseClaimsJws(token).getBody().getSubject();
		if(userId==null) {
			return null;
			}
		return new UsernamePasswordAuthenticationToken(userId, null,new ArrayList<>());
	}

}
