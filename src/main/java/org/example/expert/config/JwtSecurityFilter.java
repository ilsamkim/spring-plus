package org.example.expert.config;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtSecurityFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        String bearerJwt = request.getHeader("Authorization");

        if (bearerJwt != null && bearerJwt.startsWith("Bearer ")) {
            String jwt = jwtUtil.substringToken(bearerJwt);

            try {
                Claims claims = jwtUtil.extractClaims(jwt);
                Long userId = Long.parseLong(claims.getSubject());
                String email = claims.get("email", String.class);
                UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));
                String nickname = claims.get("nickname", String.class);

                AuthUser authUser = new AuthUser(userId, email, userRole, nickname);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        authUser, null, authUser.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                logger.error("JWT 인증 실패");
            }
        }
        filterChain.doFilter(request, response);
    }
}
