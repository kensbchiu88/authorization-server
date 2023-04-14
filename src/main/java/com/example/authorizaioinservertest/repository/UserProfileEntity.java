package com.example.authorizaioinservertest.repository;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "user_profile", schema = "auth")
@Data
public class UserProfileEntity implements UserDetails {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Column(name = "id", nullable = false)
  private int id;
  @Column(name = "username", nullable = false)
  private String username;
  @Column(name = "password", nullable = false)
  private String password;
  @Column(name = "email", nullable = false)
  private String email;
  @Column(name = "role", nullable = false)
  private String role;
  @Column(name = "worker_id", nullable = false)
  private String workerId;
  @Column(name = "department", nullable = false)
  private String department;
  @Column(name = "reason", nullable = false)
  private String reason;
  @Column(name = "is_enable", nullable = false)
  private boolean isEnable;
  @Column(name = "create_time", nullable = false)
  private Timestamp createTime;
  @Column(name = "creator", nullable = false)
  private String creator;
  @Column(name = "update_time")
  private Timestamp updateTime;
  @Column(name = "updater")
  private String updater;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Arrays.asList(new SimpleGrantedAuthority(role));
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return isEnable;
  }
}
