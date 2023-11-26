package ks.msx.jwt.controller;

import jakarta.servlet.http.HttpServletResponse;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@AllArgsConstructor
public class TestController {
    private final JwtUtility jwtUtility;

    @GetMapping("/test/endpoint/generate")
    public ResponseEntity<?> generateTokenEndpoint(HttpServletResponse response) throws NoSuchAlgorithmException {
        String token = jwtUtility.generateToken("k");
        response.addHeader(AUTHORIZATION, "Bearer " + token);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping("/test/endpoint/verify")
    public ResponseEntity<?> verifyToken(@RequestParam(name = "token")String token){
        String ExpectedUsername = "k";
        String currentUsername = jwtUtility.getUsernameFromToken(token);
        return new ResponseEntity<>(ExpectedUsername.equals(currentUsername), HttpStatus.OK);
    }
}
