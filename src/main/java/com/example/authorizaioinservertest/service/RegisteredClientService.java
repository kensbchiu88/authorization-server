package com.example.authorizaioinservertest.service;

import com.example.authorizaioinservertest.repository.ClientProfileDao;
import com.example.authorizaioinservertest.repository.ClientProfileEntity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

/**
 * 設定Authorization Server Registered Client
 */
@Service
public class RegisteredClientService {

  private final ClientProfileDao clientProfileDao;

  public RegisteredClientService(ClientProfileDao clientProfileDao) {
    this.clientProfileDao = clientProfileDao;
  }

  public List<RegisteredClient> getAll() {
    List<RegisteredClient> result = new ArrayList<>();
    List<ClientProfileEntity> clientProfileEntityList = this.clientProfileDao.findAll();
    clientProfileEntityList.stream().forEach(entity -> {
      RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
          .clientId(entity.getClientId())
//          .clientSecret(new BCryptPasswordEncoder().encode(entity.getPassword()))
          .clientSecret(entity.getPassword())
          .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
          .tokenSettings(this.tokenSettings());

      this.setRedirectUri(builder, entity.getRedirectUri());
      this.setScope(builder, entity.getScope());

      result.add(builder.build());
    });

    return result;
  }

  private void setRedirectUri(RegisteredClient.Builder builder, String redirectUriString) {
    String[] redirectUris = redirectUriString.split(";");
    Arrays.asList(redirectUris).stream().forEach(uri -> {
      System.out.println("----redirectUris----" + uri);
      builder.redirectUri(uri);
    });
  }

  private void setScope(RegisteredClient.Builder builder, String scopeString) {
    String[] scopes = scopeString.split(";");
    Arrays.asList(scopes).stream().forEach(scope -> {
      System.out.println("----scope----" + scope);
      builder.scope(scope);
    });
  }

  private TokenSettings tokenSettings() {
    return TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(60L)).build();
  }

}
