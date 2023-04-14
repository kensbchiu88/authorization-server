package com.example.authorizaioinservertest.repository;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.sql.Timestamp;
import lombok.Data;

@Entity
@Table(name = "client_profile", schema = "auth")
@Data
public class ClientProfileEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Column(name = "id", nullable = false)
  private int id;
  @Column(name = "client_id", nullable = false)
  private String clientId;
  @Column(name = "password", nullable = false)
  private String password;
  @Column(name = "scope", nullable = false)
  private String scope;
  @Column(name = "redirect_uri", nullable = false)
  private String redirectUri;
  @Column(name = "description", nullable = false)
  private String description;
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
}
