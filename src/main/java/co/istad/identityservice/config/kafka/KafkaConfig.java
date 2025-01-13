package co.istad.identityservice.config.kafka;

import co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.Map;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class KafkaConfig {

    // Topic configuration
    @Bean
    public NewTopic topic1() {
        return TopicBuilder.name("user-created-events-topic")
                .partitions(3) // Increased partitions for scalability
                .replicas(1) // Ensure proper replication based on your cluster setup
                .compact() // Compaction is good for retaining only the latest records with the same key
                .build();
    }

    @Bean
    public ConsumerFactory<String, UpdateUserEvent> consumerFactory(KafkaProperties kafkaProperties) {
        Map<String, Object> props = kafkaProperties.buildConsumerProperties();

        // Disable type mapping from headers
        props.put(JsonDeserializer.USE_TYPE_INFO_HEADERS, false);
        // Set default type to your event class
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE,
                "co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent");

        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, UpdateUserEvent> kafkaListenerContainerFactory(
            ConsumerFactory<String, UpdateUserEvent> consumerFactory) {
        ConcurrentKafkaListenerContainerFactory<String, UpdateUserEvent> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);

        // Add error handler
        factory.setCommonErrorHandler(new DefaultErrorHandler(
                (consumerRecord, exception) -> {
                    log.error("Error while processing record: {}", consumerRecord, exception);
                }
        ));

        return factory;
    }
}
