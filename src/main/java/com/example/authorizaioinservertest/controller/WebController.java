package com.example.authorizaioinservertest.controller;

import com.example.authorizaioinservertest.service.LdapService;
import com.example.authorizaioinservertest.service.UserService;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class WebController implements ErrorController {

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

  @RequestMapping("/error")
  @ResponseBody
  public String handleError(HttpServletRequest request) {
    Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

    if (status != null) {
      Integer statusCode = Integer.valueOf(status.toString());

      if(statusCode == HttpStatus.NOT_FOUND.value()) {
        return "404 NOT FOUND";
      }
      else if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
        return "500 INTERNAL SERVER ERROR";
      }
    }
    return "error";
  }


  @GetMapping("/")
  @ResponseBody
  public String index() {
    return "Welcome to the home page! ";
  }
}
