package com.example.authorizaioinservertest.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
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

  @RequestMapping("/logout")
  public void exit(HttpServletRequest request, HttpServletResponse response) {
    // token can be revoked here if needed
    new SecurityContextLogoutHandler().logout(request, null, null);

//    try {
//      //sending back to client app
//      response.sendRedirect(request.getHeader("referer"));
//    } catch (IOException e) {
//      e.printStackTrace();
//    }
  }
}
