package co.istad.identityservice.config.kafka;

import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

@Configuration
public class JacksonConfig {
    @Bean
    public Jackson2ObjectMapperBuilder jacksonBuilder() {
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.simpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS");
        builder.modules(new JavaTimeModule());
        return builder;
    }
}


