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
import java.util.Arrays;
import java.util.List;
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
            adminUser.setEmail("yithsopheaktra@gmail.com");
            adminUser.setPassword(passwordEncoder.encode("qwerqwer"));
            adminUser.setFullName("Yith Sopheaktra");
            adminUser.setProfileImage("https://avatars.githubusercontent.com/u/102577536?v=4");
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

//    @PostConstruct
//    void initOAuth2() {
//        if (clientRepository.count() < 1) {
//            // Existing client for development
//            registerClient(
//                    "code-advisor",
//                    "qwerqwer",
//                    Arrays.asList(
//                            "http://127.0.0.1:8168/login/oauth2/code/code-advisor",
//                            "http://127.0.0.1:8169/login/oauth2/code/code-advisor"
//                    )
//            );
//
//            // New client for production
//            registerClient(
//                    "code-advisor-prod",
//                    "prod-secret", // Use a different secret for production
//                    Arrays.asList(
//                            "https://code-advisors.istad.co/login/oauth2/code/code-advisor-prod"
//                    )
//            );
//        }
//    }
//
//    private void registerClient(String clientId, String clientSecret, List<String> redirectUris) {
//        TokenSettings tokenSettings = TokenSettings.builder()
//                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
//                .accessTokenTimeToLive(Duration.ofHours(1)) // Longer token lifetime for production
//                .build();
//
//        ClientSettings clientSettings = ClientSettings.builder()
//                .requireAuthorizationConsent(false)
//                .build();
//
//        var client = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId(clientId)
//                .clientSecret(passwordEncoder.encode(clientSecret))
//                .scopes(scopes -> {
//                    scopes.add("ADMIN");
//                    scopes.add("USER");
//                    scopes.add(OidcScopes.OPENID);
//                    scopes.add(OidcScopes.PROFILE);
//                    scopes.add(OidcScopes.EMAIL);
//                })
//                .redirectUris(uris -> uris.addAll(redirectUris))
//                .clientAuthenticationMethods(method -> {
//                    method.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
//                })
//                .authorizationGrantTypes(grantTypes -> {
//                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
//                })
//                .clientSettings(clientSettings)
//                .tokenSettings(tokenSettings)
//                .build();
//
//        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
//        if (registeredClient == null) {
//            jpaRegisteredClientRepository.save(client);
//        }
//    }

    @PostConstruct
    void initOAuth2() {

        if(clientRepository.count() < 1) {

            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .accessTokenTimeToLive(Duration.ofMinutes(1))
                    .build();

            ClientSettings clientSettings = ClientSettings.builder()
//                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build();

            var web = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("code-advisor")
                    .clientSecret(passwordEncoder.encode("qwerqwer")) // store in secret manager
                    .scopes(scopes -> {
                        scopes.add("ADMIN");
                        scopes.add("USER");
                        scopes.add("SCOPE_ADMIN");
                        scopes.add("SCOPE_USER");
                        scopes.add(OidcScopes.OPENID);
                        scopes.add(OidcScopes.PROFILE);
                        scopes.add(OidcScopes.EMAIL);
                    })
                    .redirectUris(uris -> {
                        uris.add("http://127.0.0.1:8168/login/oauth2/code/code-advisor");
                        uris.add("http://127.0.0.1:8169/login/oauth2/code/code-advisor");
                        uris.add("http://202.178.125.77:1168/login/oauth2/code/code-advisor");
                        uris.add("http://202.178.125.77:1169/login/oauth2/code/code-advisor");
                        uris.add("https://code-advisors.istad.co/login/oauth2/code/code-advisor");
                        uris.add("http://202.178.125.77:8168/login/oauth2/code/code-advisor");
                    })
                    .postLogoutRedirectUris(uris -> {
                        uris.add("http://127.0.0.1:8168");
                        uris.add("http://127.0.0.1:8169");
                        uris.add("http://202.178.125.77:1168");
                        uris.add("http://202.178.125.77:1169");
                        uris.add("https://code-advisors.istad.co");
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
