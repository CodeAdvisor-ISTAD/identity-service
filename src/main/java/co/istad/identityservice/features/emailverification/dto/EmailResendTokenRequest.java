package co.istad.identityservice.features.emailverification.dto;

import jakarta.validation.constraints.NotBlank;

public record EmailResendTokenRequest(
        @NotBlank(message = "Username is required")
        String username
) {
}
