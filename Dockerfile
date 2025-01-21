FROM gradle:8.4-jdk21 AS builder

WORKDIR /app

COPY . .

# Ensure gradlew has execute permissions
RUN chmod +x gradlew

# Build the application
RUN ./gradlew clean build

FROM openjdk:21-jdk

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar
COPY --from=builder /app/src/main/resources/kafka.server.keystore.jks /app/kafka.server.keystore.jks
COPY --from=builder /app/src/main/resources/kafka.server.truststore.jks /app/kafka.server.truststore.jks

EXPOSE 9090

ENTRYPOINT ["java", "-jar", "app.jar"]