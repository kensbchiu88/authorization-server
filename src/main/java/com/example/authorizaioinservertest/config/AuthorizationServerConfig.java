package com.example.authorizaioinservertest.config;

import com.example.authorizaioinservertest.repository.UserProfileDao;
import com.example.authorizaioinservertest.service.RegisteredClientService;
import com.example.authorizaioinservertest.service.UserRepositoryUserDetailsService;
import com.example.authorizaioinservertest.service.UserService;
import com.example.authorizaioinservertest.service.UserService.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthorizationServerConfig {

  @Autowired
  private UserProfileDao userProfileDao;

  @Autowired
  private RegisteredClientService registeredClientService;

  @Value("${ldap.url:}")
  private String ldapUrl;

  @Value("${ldap.base:}")
  private String ldapBase;
  @Value("${ldap.manager.dn:}")
  private String ldapManagerDn;

  @Value("${ldap.manager.password:}")
  private String ldapManagerPassword;

  @Autowired
  private UserRepositoryUserDetailsService userRepositoryUserDetailsService;

  @Autowired
  private UserService userService;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(oidc -> {
          oidc.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userInfoMapper(
              oidcUserInfoAuthenticationContext -> {
                User user = this.userService.getByWorkerId(
                    oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
                Map<String, Object> claims = new HashMap<>();
                claims.put("sub",
                    oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
                claims.put("name", user.getName());
                claims.put("email", user.getEmail());
                return new OidcUserInfo(claims);
              }));
        });

    // @formatter:off
    http
        .exceptionHandling(exceptions ->
            exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login.html"))
        )
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    // @formatter:on
    http.csrf().disable();
    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http
        .csrf().disable()
        .authorizeRequests()
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/error*").permitAll()
        .requestMatchers("/logout").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login.html")
        .failureUrl("/login.html-error.html")
        .permitAll();

    return http.build();

  }

  @Autowired
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .ldapAuthentication()
        .contextSource()
        .url(ldapUrl + ldapBase)
        .managerDn(ldapManagerDn)
        .managerPassword(ldapManagerPassword)
        .and()
        .userSearchFilter("sAMAccountName={0}");

    auth.userDetailsService(userRepositoryUserDetailsService).passwordEncoder(getPasswordEncoder());
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    return new InMemoryRegisteredClientRepository(this.registeredClientService.getAll());
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  PasswordEncoder getPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }
}