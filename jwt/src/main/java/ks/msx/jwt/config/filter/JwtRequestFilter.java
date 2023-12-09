package ks.msx.jwt.config.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ks.msx.jwt.service.UserService;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.CookieStore;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;


@Component
@AllArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final JwtUtility jwtUtility;
    private final UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //String requestToken = request.getHeader("Authorization");
//        Receive Token From HttpSession
//        String requestToken = null;
//        try{
//            requestToken = request.getSession().getAttribute("AUTHORIZATION").toString();
//        }catch (Exception e){
//            e.getStackTrace();
//        }

        // Get Token Via Cookie
        String requestToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (Objects.equals(cookie.getName(), "Authorization")) {
                        requestToken = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
                }
            }
        }

        String username = null;
        String token = null;

        if (requestToken != null && requestToken.startsWith("Bearer ")){
            token = requestToken.substring(7);
            try {
                username = jwtUtility.getUsernameFromToken(token);
            }catch (Exception e){
                System.out.println("Token expirated");
                e.getStackTrace();
            }
        }else {
            System.out.println("Warn Token does not start with Bearer");
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userService.loadUserByUsername(username);
            if (!jwtUtility.isValidToken(token)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                System.out.println(SecurityContextHolder.getContext().getAuthentication().getDetails());
            }
        }
        filterChain.doFilter(request, response);
    }
}
