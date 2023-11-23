package ks.msx.jwt.controller;

import ks.msx.jwt.service.UserService;
import ks.msx.jwt.utility.JwtUtility;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/app/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtUtility jwtUtility;

    
    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestParam(name = "username") String username, @RequestParam(name = "password")String password){
        return ResponseEntity.ok().body(HttpStatus.OK);
    }

    @GetMapping("/test")
    public ResponseEntity<?> testJwtGeneration(){
        String username = "k";
        String password = "k";
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtility.generateToken(username);
        System.out.println(token);
        return ResponseEntity.ok().body(HttpStatus.OK);
    }
}
