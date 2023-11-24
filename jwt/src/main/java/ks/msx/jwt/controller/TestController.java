package ks.msx.jwt.controller;

import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class TestController {
    private final JwtUtility jwtUtility;

    @GetMapping("/test/endpoint/generate")
    public ResponseEntity<?> generateTokenEndpoint(){
        String token = jwtUtility.generateToken("k");
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping("/test/endpoint/verify")
    public ResponseEntity<?> verifyToken(@RequestParam(name = "token")String token){
        String ExpectedUsername = "k";
        String currentUsername = jwtUtility.decodeToken(token).getSubject();
        return new ResponseEntity<>(ExpectedUsername.equals(currentUsername), HttpStatus.OK);
    }
}
