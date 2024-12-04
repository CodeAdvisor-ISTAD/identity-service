package co.istad.identityservice.features.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record UserUpdateRequest(

        @Size(max = 64, message = "Family name can not be longer than 64 characters")
        @NotEmpty(message = "Family name is required")
        String familyName,

        @Size(max = 64, message = "Given name can not be longer than 64 characters")
        @NotEmpty(message = "Given name is required")
        String givenName,

        @NotBlank(message = "Gender is required")
        String gender,

        @NotBlank(message = "Date of Birth is required")
        String dob

) {
}
