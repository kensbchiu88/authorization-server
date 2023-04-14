package com.example.authorizaioinservertest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class AuthorizaioinservertestApplication extends SpringBootServletInitializer {

  public static void main(String[] args) {
    SpringApplication.run(AuthorizaioinservertestApplication.class, args);
  }

  @Override
  protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
    return builder.sources(AuthorizaioinservertestApplication.class);
  }

}
