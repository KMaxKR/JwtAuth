package ks.msx.jwt.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.apache.catalina.Session;
import org.apache.catalina.session.StandardSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

@RestController
@AllArgsConstructor
public class TestController {
    private final JwtUtility jwtUtility;

    @GetMapping("/test/endpoint/generate")
    public ResponseEntity<?> generateTokenEndpoint(HttpServletResponse response, HttpServletRequest request) throws NoSuchAlgorithmException, IOException {
        String token = jwtUtility.generateToken("k");
        authenticate("k", "k");
//        //Send token via HttpSession
//        HttpSession session = request.getSession();
//        session.setMaxInactiveInterval(100);
//        session.setAttribute("AUTHORIZATION", token);

        // Send Token Via Cookie
        Cookie cookie =  new Cookie("Authorization", URLEncoder.encode(token, StandardCharsets.UTF_8));
        cookie.setMaxAge(10000000);
        response.addCookie(cookie);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping("/test/endpoint/verify")
    public ResponseEntity<?> returnPrincipal(){
        return new ResponseEntity<>(SecurityContextHolder.getContext().getAuthentication().toString(), HttpStatus.OK);
    }

    private void authenticate(String username, String password){
        try {
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, password));
        }catch (Exception e){
            e.getStackTrace();
        }
    }
}
