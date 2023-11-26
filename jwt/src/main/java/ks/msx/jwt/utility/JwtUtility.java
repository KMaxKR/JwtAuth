package ks.msx.jwt.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtility {
    private final static Logger logger = LoggerFactory.getLogger(JwtUtility.class);
    private final static String key = "javaLangTestJwt20RE21Specs=JRUWTaskKREFGH19";
    private final static long jwtExpirationMs = 20000000000000L;


    public String generateToken(String username) throws NoSuchAlgorithmException {
        String token = "";
        try {
            token = Jwts.builder()
                    .setSubject(username)
                    .claim("name", username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                    .signWith(SignatureAlgorithm.HS256, key)
                    .compact();
        }catch (Exception e){
            logger.error(String.valueOf(e));
        }
        return token;
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();

        return claims.getSubject();
    }
}
