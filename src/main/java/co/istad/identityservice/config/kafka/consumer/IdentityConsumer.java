package co.istad.identityservice.config.kafka.consumer;

import co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.user.UserMapper;
import co.istad.identityservice.features.user.UserRepository;
import co.istad.identityservice.features.user.dto.UpdateUserDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;

@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityConsumer {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @KafkaListener(
            topics = "user-updated-event-topic",
            groupId = "user-service",
            containerFactory = "kafkaListenerContainerFactory"
    )
    void consumeUpdateUserEvent(@Payload UpdateUserEvent updateUserEvent) {
        try {

            User existingUser = userRepository.findByUsername(updateUserEvent.getUsername())
                    .orElseThrow();


            UpdateUserDto updateUserDto = userMapper.mappedFromUpdateUserEvent(updateUserEvent);
            if (updateUserDto.getDob() == null || updateUserDto.getDob().trim().isEmpty()) {
                // Handle null/empty case - either set to null or throw exception
                existingUser.setDob(null);
            } else {
                try {
                    existingUser.setDob(LocalDate.parse(updateUserDto.getDob()));
                } catch (DateTimeParseException e) {
                    throw new IllegalArgumentException("Invalid date format. Please use YYYY-MM-DD format", e);
                }
            }
            existingUser.setFullName(updateUserDto.getFullName());
            existingUser.setGender(updateUserDto.getGender());
            existingUser.setPhoneNumber(updateUserDto.getPhoneNumber());
            existingUser.setEmail(updateUserDto.getEmail());
            existingUser.setProfileImage(updateUserDto.getProfileImage());
            existingUser.setCoverImage(updateUserDto.getCoverColor());

            log.info("consumed user: {}", existingUser);

            userRepository.save(existingUser);

            // Your processing logic here
        } catch (Exception e) {
            log.error("Error processing message: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to process message", e);
        }
    }

}
