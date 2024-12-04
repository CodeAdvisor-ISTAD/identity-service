package co.istad.identityservice.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "password_resets")
public class PasswordResets  {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, columnDefinition = "VARCHAR(128)")
    private String email;

    @Column(nullable = false, columnDefinition = "VARCHAR(256)")
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiryDateTime;

}
