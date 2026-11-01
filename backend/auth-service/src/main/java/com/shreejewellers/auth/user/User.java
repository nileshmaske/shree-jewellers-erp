package com.shreejewellers.auth.user;
import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;
@Entity
@Table(name="users")
public class User {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Column(nullable=false,unique=true) private String username;
 @Column(name="password_hash",nullable=false) private String passwordHash;
 @Column(nullable=false) private boolean enabled=true;
 @ElementCollection(fetch=FetchType.EAGER)
 @CollectionTable(name="user_roles",joinColumns=@JoinColumn(name="user_id"))
 @Column(name="role_id") private Set<Long> roleIds=new HashSet<>();
 public Long getId(){return id;}
 public String getUsername(){return username;}
 public void setUsername(String username){this.username=username;}
 public String getPasswordHash(){return passwordHash;}
 public void setPasswordHash(String passwordHash){this.passwordHash=passwordHash;}
 public boolean isEnabled(){return enabled;}
 public void setEnabled(boolean enabled){this.enabled=enabled;}
 public Set<Long> getRoleIds(){return roleIds;}
}
