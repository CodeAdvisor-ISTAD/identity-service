package co.istad.identityservice.security;

import co.istad.identityservice.security.custom.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {


    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;


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
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .anyRequest().permitAll()
//                )
//
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(Customizer.withDefaults())
//                )
//                .oauth2Login(Customizer.withDefaults())
//                .formLogin(Customizer.withDefaults())
////                .formLogin(form -> form
////                        .loginPage("/oauth2/login")
////                        .usernameParameter("gp_account")
////                        .passwordParameter("gp_password")
////                )
//                .cors(AbstractHttpConfigurer::disable)
//                .csrf(AbstractHttpConfigurer::disable);
//
//        return http.build();
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/oauth2/**", "/error","/register","/otp/**","/resend-otp","/forget-password","/reset-pwd-otp", "/reset-password", "/google","http://localhost:8168","/github").permitAll()
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
                .issuer("https://identity.istad.co")
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
        context.getClaims()
                .claim("email", user.getEmail())
                .claim("fullName", user.getFullName())
                .claim("picture", user.getPicture());
    }

    private void addGithubUserClaims(JwtEncodingContext context, DefaultOAuth2User user) {
        Map<String, Object> claims = new HashMap<>();

        String email = user.getAttribute("email");

        if (email != null) {
            claims.put("email", email);
        } else {
            claims.put("email", "random@example.com");
        }
        if (user.getAttribute("name") != null) {
            claims.put("fullName", user.getAttribute("name"));
        }
        if (user.getAttribute("avatar_url") != null) {
            claims.put("picture", user.getAttribute("avatar_url"));
        }

        claims.forEach((key, value) -> context.getClaims().claim(key, value));
    }

//    @Bean
//    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(
//            WebClient.Builder webClientBuilder) {
//        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
//
//        return request -> {
//            OAuth2User user = delegate.loadUser(request);
//
//            if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
//                return user;
//            }
//
//            OAuth2AccessToken accessToken = request.getAccessToken();
//            String email = (String) webClientBuilder.build()
//                    .get()
//                    .uri("https://api.github.com/user/emails")
//                    .headers(h -> h.setBearerAuth(accessToken.getTokenValue()))
//                    .retrieve()
//                    .bodyToMono(List.class)
//                    .block()
//                    .stream()
//                    .filter(emailObj -> (boolean) ((Map) emailObj).get("primary"))
//                    .map(emailObj -> (String) ((Map) emailObj).get("email"))
//                    .findFirst()
//                    .orElse(null);
//
//            Map<String, Object> attrs = new HashMap<>(user.getAttributes());
//            attrs.put("email", email);
//
//            return new DefaultOAuth2User(user.getAuthorities(), attrs, "id");
//        };
//    }

}



