package co.istad.identityservice.features.auth;

import co.istad.identityservice.base.BasedMessage;
import co.istad.identityservice.features.auth.dto.ChangePasswordRequest;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.user.dto.UserBasicInfoRequest;
import co.istad.identityservice.features.user.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authService.register(registerRequest));
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @GetMapping("/me")
    UserResponse findMe(Authentication authentication) {
        return authService.findMe(authentication);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @PutMapping("/me")
    UserResponse updateMeBasicInfo(Authentication authentication,
                                   @Valid @RequestBody UserBasicInfoRequest userBasicInfoRequest) {
        return authService.updateMeBasicInfo(authentication, userBasicInfoRequest);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @PutMapping("/me/change-password")
    BasedMessage changePassword(Authentication authentication,
                                @Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
        authService.changePassword(authentication, changePasswordRequest);
        return new BasedMessage("Password has been changed");
    }

}
