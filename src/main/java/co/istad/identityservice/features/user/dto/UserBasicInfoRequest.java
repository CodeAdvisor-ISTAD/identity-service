package co.istad.identityservice.features.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record UserBasicInfoRequest(

		@Size(max = 64, message = "Family name can not be longer than 64 characters")
		@NotEmpty(message = "Family name is required")
		String fullName

) {
}
