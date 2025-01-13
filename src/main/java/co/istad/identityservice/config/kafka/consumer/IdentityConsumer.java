package co.istad.identityservice.config.kafka.consumer;

import co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.user.UserMapper;
import co.istad.identityservice.features.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityConsumer {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @KafkaListener(
            topics = "user-service-topic",
            groupId = "user-service",
            containerFactory = "kafkaListenerContainerFactory"
    )
    void consumeUpdateUserEvent(@Payload UpdateUserEvent updateUserEvent) {
        try {
            log.info("Received message: {}", updateUserEvent);

            User user = userMapper.mappedFromUpdateUserEvent(updateUserEvent);
            userRepository.save(user);

            // Your processing logic here
        } catch (Exception e) {
            log.error("Error processing message: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to process message", e);
        }
    }

}
