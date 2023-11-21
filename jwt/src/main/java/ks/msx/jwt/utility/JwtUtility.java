package ks.msx.jwt.utility;

import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import ks.msx.jwt.entity.User;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtility {
    private final static Logger logger = LoggerFactory.getLogger(JwtUtility.class);

    private String key = "javaKeyProject";
    private long jwtExpirationMs = 2000;
    private String jwtCookies;

    public String getJwtFromCookies(HttpServletRequest request){
        Cookie cookie = WebUtils.getCookie(request, jwtCookies);
        if (cookie != null){
            return cookie.getValue();
        }else {
            return null;
        }
    }

    public ResponseCookie generateJwtCookie(User user){
        String jwt = generateToken(user.getUsername());
        return ResponseCookie.from(jwtCookies, jwt).path("/app").build();
    }

    public ResponseCookie getCleanJwtCookie(){
        return ResponseCookie.from(jwtCookies).path("/app").build();
    }

    public String getUsernameFromToken(String token){
        return Jwts
                .parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().setSigningKey(key).build().parse(authToken);
            return true;
        }catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public String generateToken(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, key)
                .compact();
    }
}
