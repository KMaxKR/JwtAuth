package ks.msx.jwt.controller;

import ks.msx.jwt.service.UserService;
import ks.msx.jwt.utility.JwtUtility;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/app/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtility jwtUtility;
    // TODO: 13.11.2023 to finish endpoints and other methods 
    
    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestParam(name = "username") String username, @RequestParam(name = "password")String password){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return ResponseEntity.ok().body(HttpStatus.OK);
    }
}