package co.istad.identityservice.test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class Controller {
    @GetMapping("/token")
    public String getToken(Authentication authentication) {
        // Check if the authentication is a valid OAuth2 token
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
            // You can access the token directly from the authentication object
            return jwtToken.getToken().getTokenValue(); // Return the access token value
        }
        return "No valid token found";
    }

}
