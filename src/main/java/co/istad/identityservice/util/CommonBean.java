package co.istad.identityservice.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class CommonBean {

    @Bean
    ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

}
