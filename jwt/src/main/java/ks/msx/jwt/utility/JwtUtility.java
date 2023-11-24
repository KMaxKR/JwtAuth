package ks.msx.jwt.utility;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtility {
    private final static Logger logger = LoggerFactory.getLogger(JwtUtility.class);
    private final static String key = "javaKeyProject";
    private final static long jwtExpirationMs = 2000L;


    public String generateToken(String username){
        try {
            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                    .signWith(SignatureAlgorithm.HS512, key)
                    .compact();
        }catch (Exception e){
            logger.error(String.valueOf(e));
        }
        return null;
    }

    public Claims decodeToken(String token){
        return Jwts.parser().build().parseSignedClaims(token).getPayload();
    }
}
