package com.shreejewellers.auth.security;
import com.shreejewellers.auth.user.*;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
public class SecurityConfig {
 @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}
 @Bean UserDetailsService userDetailsService(UserRepository users, RoleRepository roles){
  return username->{
   User user=users.findByUsername(username).orElseThrow(()->new UsernameNotFoundException("Invalid credentials"));
   List<SimpleGrantedAuthority> authorities=roles.findByIdIn(user.getRoleIds()).stream().map(r->new SimpleGrantedAuthority("ROLE_"+r.getName())).toList();
   return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPasswordHash(),user.isEnabled(),true,true,true,authorities);
  };
 }
 @Bean AuthenticationManager authenticationManager(UserDetailsService details,PasswordEncoder encoder){
  DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
  provider.setUserDetailsService(details);provider.setPasswordEncoder(encoder);
  return new ProviderManager(provider);
 }
 @Bean SecretKeySpec jwtKey(@Value("${security.jwt.secret}") String secret){
  byte[] bytes=secret.getBytes(StandardCharsets.UTF_8);
  if(bytes.length<32)throw new IllegalArgumentException("JWT_SECRET must be at least 32 bytes");
  return new SecretKeySpec(bytes,"HmacSHA256");
 }
 @Bean JwtEncoder jwtEncoder(SecretKeySpec key){return new NimbusJwtEncoder(new ImmutableSecret<>(key));}
 @Bean JwtDecoder jwtDecoder(SecretKeySpec key){return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();}
 @Bean JwtAuthenticationConverter jwtAuthenticationConverter(){
  JwtAuthenticationConverter converter=new JwtAuthenticationConverter();
  converter.setJwtGrantedAuthoritiesConverter(jwt->{
   List<String> roles=jwt.getClaimAsStringList("roles");
   return roles==null?List.of():roles.stream().map(SimpleGrantedAuthority::new).toList();
  });return converter;
 }
 @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,JwtAuthenticationConverter converter)throws Exception{
  return http.csrf(csrf->csrf.disable())
   .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .authorizeHttpRequests(a->a.requestMatchers(HttpMethod.POST,"/api/auth/login").permitAll()
     .requestMatchers("/api/auth/admin/**").hasRole("ADMIN")
     .anyRequest().authenticated())
   .oauth2ResourceServer(o->o.jwt(j->j.jwtAuthenticationConverter(converter)))
   .build();
 }
}
