package ks.msx.jwt.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@AllArgsConstructor
public class TestController {
    private final JwtUtility jwtUtility;

    @GetMapping("/test/endpoint/generate")
    public ResponseEntity<?> generateTokenEndpoint(HttpServletResponse response) throws NoSuchAlgorithmException, IOException {
        String token = jwtUtility.generateToken("k");
        response.setHeader(AUTHORIZATION, "Bearer "+token);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping("/test/endpoint/verify")
    public ResponseEntity<?> verifyToken(HttpServletRequest request){
        String ExpectedUsername = "k";
        String currentUsername = jwtUtility.getUsernameFromToken(String.valueOf(request.getHeaders(AUTHORIZATION)));
        String header = String.valueOf(request.getHeaders(AUTHORIZATION));
        System.out.println(header);
        return new ResponseEntity<>(ExpectedUsername.equals(currentUsername), HttpStatus.OK);
    }
}
