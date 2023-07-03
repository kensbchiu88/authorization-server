package com.example.authorizaioinservertest.service;

import com.example.authorizaioinservertest.repository.UserProfileDao;
import com.example.authorizaioinservertest.repository.UserProfileEntity;
import com.example.authorizaioinservertest.service.LdapService.LdapUser;
import java.util.Optional;
import lombok.Builder;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** 取得登入的User資訊 */
@Service
public class UserService {
  @Autowired private LdapService ldapService;
  @Autowired private UserProfileDao userProfileDao;

  /** 取得登入的User資訊 */
  public User getByWorkerId(String workerId) {
    User user;
    Optional<LdapUser> ldapUserOpt = this.ldapService.getPerson(workerId);
    if(ldapUserOpt.isEmpty()) {
      UserProfileEntity userProfile = this.userProfileDao.findByUsername(workerId);
      user = User.builder().account(workerId).name(userProfile.getUsername()).email(userProfile.getEmail()).build();
    } else {
      user = User.builder().account(workerId).name(ldapUserOpt.get().getName()).email(ldapUserOpt.get().getEmail()).build();
    }
    
    return user;
  }


  @Data
  @Builder
  public static class User {
    private String account;
    private String name;
    private String email;
  }
}
