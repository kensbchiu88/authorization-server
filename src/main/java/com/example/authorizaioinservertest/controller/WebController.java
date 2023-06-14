package com.example.authorizaioinservertest.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class WebController {
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
}
