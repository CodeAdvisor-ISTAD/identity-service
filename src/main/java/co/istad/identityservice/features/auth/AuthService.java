package co.istad.identityservice.features.auth;


import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.auth.dto.ChangePasswordRequest;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.auth.dto.ResetPasswordRequest;
import co.istad.identityservice.features.user.dto.UserBasicInfoRequest;
import co.istad.identityservice.features.user.dto.UserResponse;
import org.springframework.security.core.Authentication;

import java.util.Optional;

public interface AuthService {

	String register(RegisterRequest registerRequest);

	UserResponse findMe(Authentication authentication);

	Optional<UserResponse> findByEmail(String email);

	UserResponse updateMeBasicInfo(Authentication authentication, UserBasicInfoRequest userBasicInfoRequest);

	void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest);

	void isNotAuthenticated(Authentication authentication);

	String forgetPassword(String email);

	void resetPassword(ResetPasswordRequest resetPasswordRequest);

	UserResponse createUser(User user);

}
