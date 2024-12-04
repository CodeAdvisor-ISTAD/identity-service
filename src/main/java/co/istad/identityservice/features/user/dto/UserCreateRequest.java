package co.istad.identityservice.features.user.dto;

import jakarta.validation.constraints.*;
import lombok.Builder;

import java.util.List;

@Builder
public record UserCreateRequest(

        @NotEmpty(message = "Username is required")
        @Size(min = 5, message = "Username must be at least 5 characters long")
        @Size(max = 32, message = "Username can not be longer than 32 characters")
        String username,

        @NotEmpty(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 5 characters long")
        @Size(max = 32, message = "Password can not be longer than 32 characters")
        String password,

        @NotEmpty(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotBlank(message = "Phone number is required")
        String phoneNumber,

        @Size(max = 64, message = "Family name can not be longer than 64 characters")
        @NotEmpty(message = "Family name is required")
        String familyName,

        @Size(max = 64, message = "Given name can not be longer than 64 characters")
        @NotEmpty(message = "Given name is required")
        String givenName,

        @NotBlank(message = "Gender is required")
        String gender,

        @NotBlank(message = "Date of Birth is required")
        String dob,

        @NotEmpty(message = "Authority is required at least one")
        List<@NotBlank(message = "Authority name is required") String> authorities

) {
}
