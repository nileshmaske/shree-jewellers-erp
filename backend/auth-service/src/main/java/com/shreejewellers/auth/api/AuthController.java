package com.shreejewellers.auth.api;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
 private final AuthenticationManager manager;
 private final JwtEncoder encoder;
 private final String issuer;
 public AuthController(AuthenticationManager manager,JwtEncoder encoder,@Value("${security.jwt.issuer}")String issuer){this.manager=manager;this.encoder=encoder;this.issuer=issuer;}
 public record LoginRequest(@NotBlank String username,@NotBlank String password){}
 public record TokenResponse(String accessToken,String tokenType,long expiresIn){}
 @PostMapping("/login")
 public TokenResponse login(@Valid @RequestBody LoginRequest request){
  try{
   Authentication auth=manager.authenticate(new UsernamePasswordAuthenticationToken(request.username(),request.password()));
   Instant now=Instant.now();
   List<String> roles=auth.getAuthorities().stream().map(a->a.getAuthority()).toList();
   JwtClaimsSet claims=JwtClaimsSet.builder().issuer(issuer).subject(auth.getName()).issuedAt(now)
    .expiresAt(now.plus(15,ChronoUnit.MINUTES)).claim("roles",roles).build();
   JwsHeader header=JwsHeader.with(org.springframework.security.oauth2.jose.jws.MacAlgorithm.HS256).build();
   return new TokenResponse(encoder.encode(JwtEncoderParameters.from(header,claims)).getTokenValue(),"Bearer",900);
  }catch(BadCredentialsException e){throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid credentials");}
 }
 @GetMapping("/me")
 public Map<String,Object> me(Authentication auth){return Map.of("username",auth.getName(),"authorities",auth.getAuthorities().stream().map(a->a.getAuthority()).toList());}
 @GetMapping("/admin/check")
 public Map<String,String> adminCheck(){return Map.of("status","ADMIN_ACCESS_GRANTED");}
}
