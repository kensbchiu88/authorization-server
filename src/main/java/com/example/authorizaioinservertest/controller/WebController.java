package com.example.authorizaioinservertest.controller;

import com.example.authorizaioinservertest.service.LdapService;
import com.example.authorizaioinservertest.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class WebController {

  @Autowired
  private UserService userService;

  @Autowired
  private LdapService ldapService;

  // Login form
  @RequestMapping("/login.html")
  public String login() {
    return "login.html";
  }

  // Login form with error
  @RequestMapping("/login.html-error.html")
  public String loginError(Model model) {
    model.addAttribute("loginError", true);
    return "login.html";
  }

  @RequestMapping("/logout")
  public void exit(HttpServletRequest request, HttpServletResponse response) {
    // token can be revoked here if needed
    new SecurityContextLogoutHandler().logout(request, null, null);
  }

//  @GetMapping("/")
//  @ResponseBody
//  public String index() {
//    User user = this.userService.getByWorkerId("admin");
//    return "Welcome to the home page! " + user.getName();
//  }
}
