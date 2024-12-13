package co.istad.identityservice.features.user.dto;

import lombok.Builder;

@Builder
public record UserResponse(

    String username,
    String uuid,
    String email,
    String profileImage,
    String familyName,
    String givenName

) {
    
}
