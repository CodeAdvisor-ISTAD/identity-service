package co.istad.identityservice.security;

import co.istad.identityservice.domain.Authority;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.domain.UserAuthority;
import co.istad.identityservice.features.authority.AuthorityRepository;
import co.istad.identityservice.features.user.UserRepository;
import co.istad.identityservice.security.repository.ClientRepository;
import co.istad.identityservice.security.repository.JpaRegisteredClientRepository;
import jakarta.annotation.PostConstruct;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDate;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class Init {

    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;

    @PostConstruct
    void initUserDetails() {

        if (userRepository.count() < 1) {

            // Authority initialization
            Authority user = new Authority();
            user.setName("USER");
            authorityRepository.save(user);

            Authority admin = new Authority();
            admin.setName("ADMIN");
            authorityRepository.save(admin);


            // User initialization
            User adminUser = new User();
            adminUser.setUuid(UUID.randomUUID().toString());
            adminUser.setUsername("admin");
            adminUser.setEmail("mengseu2004@gmail.com");
            adminUser.setPassword(passwordEncoder.encode("qwerqwer"));
            adminUser.setFullName("HelloBroBro");
            adminUser.setProfileImage("avatar.png");
            adminUser.setCoverImage("cover.png");
            adminUser.setDob(LocalDate.now());
            adminUser.setGender("Male");
            adminUser.setPhoneNumber("0967174832");
            adminUser.setEmailVerified(true);
            adminUser.setIsEnabled(true);
            adminUser.setCredentialsNonExpired(true);
            adminUser.setAccountNonLocked(true);
            adminUser.setAccountNonExpired(true);

            // start setup user authorities for admin
            UserAuthority defaultUserAuthority = new UserAuthority(); // default
            defaultUserAuthority.setUser(adminUser);
            defaultUserAuthority.setAuthority(user);

            UserAuthority adminAuthority = new UserAuthority(); // admin
            adminAuthority.setUser(adminUser);
            adminAuthority.setAuthority(admin);

            adminUser.setUserAuthorities(Set.of(defaultUserAuthority, adminAuthority));
            // end setup user authorities for admin
            userRepository.save(adminUser);

        }

    }

    @PostConstruct
    void initOAuth2() {

        if(clientRepository.count() < 1) {

            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(1))
                    .build();

            ClientSettings clientSettings = ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build();

            var web = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("code-advisor")
                    .clientSecret(passwordEncoder.encode("qwerqwer")) // store in secret manager
                    .scopes(scopes -> {
                        scopes.add(OidcScopes.OPENID);
                        scopes.add(OidcScopes.PROFILE);
                        scopes.add(OidcScopes.EMAIL);
                    })
                    .redirectUris(uris -> {
                        uris.add("http://127.0.0.1:9090/login/oauth2/code/code-advisor");
                        uris.add("http://127.0.0.1:8168/login/oauth2/code/code-advisor");
                        uris.add("http://localhost:9090/login/oauth2/code/google");
                        uris.add("http://localhost:8168/login/oauth2/code/google");

                    })
                    .postLogoutRedirectUris(uris -> {
                        uris.add("http://127.0.0.1:8168");
                    })
                    .clientAuthenticationMethods(method -> {
                        method.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    }) //TODO: grant_type:client_credentials, client_id & client_secret, redirect_uri
                    .authorizationGrantTypes(grantTypes -> {
                        grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                        grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                    })
                    .clientSettings(clientSettings)
                    .tokenSettings(tokenSettings)
                    .build();

            RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId("codeadvisor");

            if (registeredClient == null) {
                jpaRegisteredClientRepository.save(web);
            }
        }

    }

}
