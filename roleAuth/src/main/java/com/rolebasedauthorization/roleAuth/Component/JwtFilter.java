package com.rolebasedauthorization.roleAuth.Component;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.rolebasedauthorization.roleAuth.Service.JwtUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtUserDetailsService jwtUserDetailsService;
	
	@Autowired
	private TokenManager tokenManager;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		  String tokenHeader = request.getHeader("Authorization");
	      String username = null;
	      String token = null;
	      if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
	         token = tokenHeader.substring(7);
	         try {
	            username = tokenManager.getUsernameFromToken(token);
	         } catch (IllegalArgumentException e) {
	            System.out.println("Unable to get JWT Token");
	         } catch (ExpiredJwtException e) {
	            System.out.println("JWT Token has expired");
	         }
	      } else {
	         System.out.println("Bearer String not found in token");
	      }
	      if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	         UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
	         if (tokenManager.validateJwtToken(token, userDetails)) {
	            UsernamePasswordAuthenticationToken
	            authenticationToken = new UsernamePasswordAuthenticationToken(
	            userDetails, null, userDetails.getAuthorities());
	            
	            authenticationToken.setDetails(new
	            WebAuthenticationDetailsSource().buildDetails(request));
	            
	            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
	         }
	      }
	      filterChain.doFilter(request, response);
		
	}

}
