package co.istad.identityservice.features.passwordreset;

import co.istad.identityservice.domain.PasswordResets;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordResetsRepository extends CrudRepository<PasswordResets, Long> {

    Optional<PasswordResets> findByToken(String token);
    
}
