package co.istad.identityservice.features.emailverification;



import co.istad.identityservice.domain.EmailVerificationToken;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.emailverification.dto.EmailVerifyRequest;

public interface EmailVerificationTokenService {

    void verify(EmailVerifyRequest emailVerifyRequest);

    boolean isUsersToken(EmailVerificationToken token, User user);

    boolean isTokenInDb(EmailVerificationToken token, String tokenToVerify);

    void generate(User user);

    boolean isExpired(EmailVerificationToken token);

    void resend(String username);

}
