package com.example.authorizaioinservertest.config;


import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class LdapConfiguration {

  @Value("${ldap.url:}")
  private String ldapUrl;

  @Value("${ldap.base:}")
  private String ldapBase;
  @Value("${ldap.manager.dn:}")
  private String ldapManagerDn;

  @Value("${ldap.manager.password:}")
  private String ldapManagerPassword;

  @Bean
  public LdapContextSource contextSource() {
    LdapContextSource contextSource = new LdapContextSource();
    contextSource.setUrl(ldapUrl);
    contextSource.setBase(ldapBase);
    contextSource.setUserDn(ldapManagerDn);
    contextSource.setPassword(ldapManagerPassword);
    contextSource.setPooled(true);

    // 乱码问题
    Map<String, Object> config = new HashMap<>();
    config.put("java.naming.ldap.attributes.binary", "objectGUID");
    contextSource.setBaseEnvironmentProperties(config);

    return contextSource;
  }

  @Bean
  public LdapTemplate ldapTemplate(LdapContextSource contextSource) {
    return new LdapTemplate(contextSource);
  }
}
