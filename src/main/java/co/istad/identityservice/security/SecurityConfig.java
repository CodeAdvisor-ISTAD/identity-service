package co.istad.identityservice.security;

import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.user.UserRepository;
import co.istad.identityservice.features.user.UserService;
import co.istad.identityservice.security.custom.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {


    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Value("${code-advisors.ip}")
    private String codeAdvisorIp;

    @Value("${code-advisors.port}")
    private String codeAdvisorPort;



    @Bean
    WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }


    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    @Bean
    @Order(1)
    SecurityFilterChain configureOAuth2(HttpSecurity http) throws Exception {


        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                /*.authorizationEndpoint(endpoint -> endpoint
                        .consentPage("/oauth2/consent")
                )*/
                .oidc(Customizer.withDefaults());


        http
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );


        return http.build();
    }


    @Bean
    @Order(2)
    SecurityFilterChain configureHttpSecurity(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login","/logout","/oauth2/**", "/error", "/register", "/otp/**", "/resend-otp", "/forget-password", "/reset-pwd-otp", "/reset-password", "/google", "http://localhost:8168", "/github").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                                .loginPage("/login")
                                .loginProcessingUrl("/login")
//                        .defaultSuccessUrl("http://localhost:8168/", true)
                                .failureUrl("/login?error=true")
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("http://"+codeAdvisorIp+":"+codeAdvisorPort)
//                        .logoutSuccessUrl("http://127.0.0.1:8168")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID") // Add any other cookies you need to clear
                        .deleteCookies("SESSION")
                        .addLogoutHandler(new SecurityContextLogoutHandler())
                )

                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }


    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();
            Object principal = authentication.getPrincipal();

            if (context.getTokenType().getValue().equals("id_token")) {
                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof DefaultOidcUser oidcUser) {
                    addGoogleUserClaims(context, oidcUser);
                } else if (principal instanceof DefaultOAuth2User oauth2User) {
                    addGithubUserClaims(context, oauth2User);
                }
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                addStandardClaims(context, authentication);

                if (principal instanceof CustomUserDetails customUserDetails) {
                    addCustomUserClaims(context, customUserDetails);
                } else if (principal instanceof DefaultOidcUser oidcUser) {
                    addGoogleUserClaims(context, oidcUser);
                } else if (principal instanceof DefaultOAuth2User oauth2User) {
                    addGithubUserClaims(context, oauth2User);
                }
            }
        };
    }

    private void addStandardClaims(JwtEncodingContext context, Authentication authentication) {
        Set<String> scopes = new HashSet<>(context.getAuthorizedScopes());
        authentication.getAuthorities()
                .forEach(auth -> scopes.add(auth.getAuthority()));

        context.getClaims()
//                .issuer("https://identity.istad.com") custom issuer is not working
                .id(authentication.getName())
                .subject(authentication.getName())
                .claim("scope", scopes);
    }

    private void addCustomUserClaims(JwtEncodingContext context, CustomUserDetails user) {
        context.getClaims()
                .claim("userUuid", user.getUser().getUuid())
                .claim("username", user.getUser().getUsername())
                .claim("fullName", user.getUser().getFullName())
                .claim("email", user.getUser().getEmail());
    }

    private void addGoogleUserClaims(JwtEncodingContext context, DefaultOidcUser user) {
        String email = user.getEmail();
        userRepository.findByEmail(email)
                .ifPresentOrElse(
                        userEntity -> {
                            context.getClaims()
                                    .claim("userUuid", userEntity.getUuid())
                                    .claim("username", userEntity.getUsername())
                                    .claim("fullName", userEntity.getFullName())
                                    .claim("profileImage", userEntity.getProfileImage())
                                    .claim("email", userEntity.getEmail());

                        },
                        () -> {
                            context.getClaims()
                                    .claim("email", email)
                                    .claim("fullName", user.getFullName());
                        }
                );

    }

    private void addGithubUserClaims(JwtEncodingContext context, DefaultOAuth2User user) {
        Map<String, Object> claims = new HashMap<>();

        User user1 = userRepository.findByUsername(user.getAttribute("login")).orElse(null);

        if (user1 != null) {
            claims.put("userUuid", user1.getUuid());
            claims.put("username", user1.getUsername());
            claims.put("email", user.getAttribute("login")+ "@github.com");
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("avatar_url") != null) {
            claims.put("profileImage", user.getAttribute("avatar_url"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }

}



