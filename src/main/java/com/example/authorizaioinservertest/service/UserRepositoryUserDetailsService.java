package com.example.authorizaioinservertest.service;

import com.example.authorizaioinservertest.repository.UserProfileDao;
import com.example.authorizaioinservertest.repository.UserProfileEntity;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserRepositoryUserDetailsService implements UserDetailsService {

  private final UserProfileDao userProfileDao;

  @Autowired
  public UserRepositoryUserDetailsService(UserProfileDao userProfileDao) {
    this.userProfileDao = userProfileDao;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserProfileEntity user = this.userProfileDao.findByUsername(username);
    if (Objects.isNull(user)) {
      throw new UsernameNotFoundException("User:" + username + " not found");
    }
    return user;
  }
}
