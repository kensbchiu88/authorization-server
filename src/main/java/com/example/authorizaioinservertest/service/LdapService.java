package com.example.authorizaioinservertest.service;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.List;
import java.util.Optional;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

/**
 * 抓取Ldap user資訊
 */
@Service
@Slf4j
public class LdapService {

  @Autowired
  private LdapTemplate ldapTemplate;

  public Optional<LdapUser> getPerson(String workerId) {
    try{
      List<LdapUser> people = ldapTemplate.search(query().where("sAMAccountName").is(workerId), new PersonAttributesMapper());
      return ((null != people && !people.isEmpty()) ? Optional.of(people.get(0)) : Optional.empty());
    } catch (NullPointerException e1) {
      log.info("can not find user info in LDAP. worker id:"+workerId);
      return Optional.empty();
    } catch (Exception e2) {
      log.error("get LDAP error:" + e2.getMessage());
      return Optional.empty();
    }

  }

  private class PersonAttributesMapper implements AttributesMapper<LdapUser> {
    public LdapUser mapFromAttributes(Attributes attributes) throws NamingException {
      LdapUser person = new LdapUser();
      person.setAccount(null != attributes.get("sAMAccountName") ? (String) attributes.get("sAMAccountName").get() : null);
      person.setName((String) attributes.get("displayName").get());
      person.setEmail((String) attributes.get("mail").get());
      return person;
    }
  }

  /** Ldap user 資訊*/
  @Data
  public static class LdapUser {
    private String account;
    private String name;
    private String email;
  }

}
