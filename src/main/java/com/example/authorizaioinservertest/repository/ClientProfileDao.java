package com.example.authorizaioinservertest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientProfileDao extends JpaRepository<ClientProfileEntity, Integer> {

}
