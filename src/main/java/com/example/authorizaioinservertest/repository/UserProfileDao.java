package com.example.authorizaioinservertest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserProfileDao extends JpaRepository<UserProfileEntity, Integer> {

  UserProfileEntity findByUsername(String username);
}
