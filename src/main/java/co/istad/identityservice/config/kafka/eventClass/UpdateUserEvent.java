package co.istad.identityservice.config.kafka.eventClass;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

@Data
@Builder
@NoArgsConstructor  // This is crucial for deserialization
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateUserEvent {
    private String id;
    private String authorUuid;
    private String fullName;
    private String username;
    private String gender;
    private String phoneNumber;
    private String email;
    private String bio;
    private String workPlace;
    private String pob;
    private String school;
    private String jobPosition;
    private String dob;
    private String profileImage;
    private boolean isDeleted;
    private String coverColor;
    private String achievementLevel;
}


