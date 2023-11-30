package ks.msx.jwt.controller;

import jakarta.servlet.http.HttpServletResponse;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RestController
@AllArgsConstructor
public class TestController {
    private final JwtUtility jwtUtility;

    @GetMapping("/test/endpoint/generate")
    public ResponseEntity<?> generateTokenEndpoint(HttpServletResponse response) throws NoSuchAlgorithmException, IOException {
        String token = jwtUtility.generateToken("k");
        authenticate("k", "k");
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
