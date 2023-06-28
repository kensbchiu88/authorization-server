package com.example.authorizaioinservertest.config;

import com.example.authorizaioinservertest.repository.UserProfileDao;
import com.example.authorizaioinservertest.repository.UserProfileEntity;
import com.example.authorizaioinservertest.service.RegisteredClientService;
import com.example.authorizaioinservertest.service.UserRepositoryUserDetailsService;
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
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
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

  @Value("${ldap.manager.dn:}")
  private String ldapManagerDn;

  @Value("${ldap.manager.password:}")
  private String ldapManagerPassword;

  @Autowired
  private UserRepositoryUserDetailsService userRepositoryUserDetailsService;

//  @Autowired
//  private DaoAuthenticationProvider daoAuthenticationProvider;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
//    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    String currentPrincipleName = authentication.getName();
//    System.out.println("----currentPrincipleName----" + currentPrincipleName);

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        //.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        .oidc(oidc -> {
          oidc.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userInfoMapper(
              oidcUserInfoAuthenticationContext -> {
                UserProfileEntity userProfile = this.userProfileDao.findByUsername(
                    oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
                OAuth2AccessToken accessToken = oidcUserInfoAuthenticationContext.getAccessToken();
                Map<String, Object> claims = new HashMap<>();
//                        claims.put("url", "https://github.com/ITLab1024");
                //claims.put("accessToken", accessToken);
                claims.put("sub",
                    oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
                claims.put("name", oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
//                claims.put("email", userProfile.getEmail());
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
        .requestMatchers( "/public/**").permitAll()
        .requestMatchers("/error*").permitAll()
        .requestMatchers("/logout").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login.html")
        .failureUrl("/login.html-error.html")
        .permitAll();


/*
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated()
        )
        // Form login.html handles the redirect to the login.html page from the
        // authorization server filter chain
        .formLogin(Customizer.withDefaults())
        .csrf().disable();
*/

    return http.build();

  }

  @Autowired
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .ldapAuthentication()
        .contextSource()
        .url("ldap://10.35.1.203:3268/dc=fit,dc=com")
        .managerDn(ldapManagerDn)
        .managerPassword(ldapManagerPassword)
        .and()
        .userSearchFilter("sAMAccountName={0}");

    auth.userDetailsService(userRepositoryUserDetailsService).passwordEncoder(getPasswordEncoder());
//    auth.
//    auth.authenticationProvider(daoAuthenticationProvider);
  }
//  @Autowired
//  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//    auth.userDetailsService(userRepositoryUserDetailsService).passwordEncoder(getPasswordEncoder());
//  }

//  @Bean
//  public <CustomLdapUserDetailsMapper> ActiveDirectoryLdapAuthenticationProvider getAdAuthProvider(CustomLdapUserDetailsMapper customLdapUserDetailsMapper) {
//    ActiveDirectoryLdapAuthenticationProvider authProvider = new ActiveDirectoryLdapAuthenticationProvider(domain, urls);
//    authProvider.setSearchFilter("(&(objectClass=user)(sAMAccountName={1}))");
//    authProvider.setUserDetailsContextMapper(customLdapUserDetailsMapper);
//    return authProvider;
//  }
//
//  @Bean
//  public <CustomDatabaseUserDetailsService> DaoAuthenticationProvider getDaoAuthProvider(CustomDatabaseUserDetailsService customDatabaseUserDetailsService) {
//    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//    provider.setUserDetailsService(userRepositoryUserDetailsService);
//    provider.setPasswordEncoder(getPasswordEncoder());
//    return provider;
//  }

//  @Bean
//  public UserDetailsService userDetailsService() {
//    UserDetails userDetails = User.withDefaultPasswordEncoder()
//        .username("admin")
//        .password("1111")
//        .roles("USER")
//        .build();
//
//    return new InMemoryUserDetailsManager(userDetails);
//        /*
//        UserDetails user2 = User.withDefaultPasswordEncoder()
//                .username("test")
//                .password("test")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user,user2);
//         */
//  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    /*
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("dmp-api")
        .clientSecret(new BCryptPasswordEncoder().encode("1111"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://127.0.0.1:8000/login/oauth2/code/articles-client-oidc")
        .redirectUri("http://127.0.0.1:8001/token")
        .redirectUri("http://127.0.0.1:8000/authorized")
        //.redirectUri("http://127.0.0.1:8000/gettoken")
        //.redirectUri("http://172.20.10.2:3000/login/generic_oauth")
        //.redirectUri("http://localhost:3000/login/generic_oauth")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
//        .scope("articles.read")
        //.scope("message.write")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .tokenSettings(tokenSettings())
        .build();

    RegisteredClient registeredClient1 = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("grafana")
        .clientSecret(new BCryptPasswordEncoder().encode("1111"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://127.0.0.1:8000/login/oauth2/code/grafana-oidc")
        .redirectUri("http://127.0.0.1:8001/token")
//        .redirectUri("http://127.0.0.1:8000/authorized")
        .redirectUri("http://172.20.10.3:3000/login/generic_oauth")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .scope("articles.read")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .tokenSettings(tokenSettings())
        .build();

    return new InMemoryRegisteredClientRepository(registeredClient, registeredClient1);
    */

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

  /*
  @Bean
  public TokenSettings tokenSettings() {
    return TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(60L)).build();
  }

   */
}