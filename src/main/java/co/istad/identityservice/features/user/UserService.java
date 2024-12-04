package co.istad.identityservice.features.user;


import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.user.dto.UserBasicInfoRequest;
import co.istad.identityservice.features.user.dto.UserCreateRequest;
import co.istad.identityservice.features.user.dto.UserPasswordResetResponse;
import co.istad.identityservice.features.user.dto.UserResponse;
import org.springframework.data.domain.Page;

public interface UserService {

    UserResponse updateBasicInfo(String username, UserBasicInfoRequest userBasicInfoRequest);

    UserPasswordResetResponse resetPassword(String username);

    void enable(String username);

    void disable(String username);

    void createNewUser(UserCreateRequest userCreateRequest);

    Page<UserResponse> findList(int pageNumber, int pageSize);

    UserResponse findByUsername(String username);

    void checkForPasswords(String password, String confirmPassword);

    void checkTermsAndConditions(String value);

    void existsByUsername(String username);

    void existsByEmail(String email);

    void verifyEmail(User user);

    void checkForOldPassword(String username, String oldPassword);

    void processOAuthPostLogin(String username);

}
