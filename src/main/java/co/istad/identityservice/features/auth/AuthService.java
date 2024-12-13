package co.istad.identityservice.features.auth;


import co.istad.identityservice.features.auth.dto.ChangePasswordRequest;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.user.dto.UserBasicInfoRequest;
import co.istad.identityservice.features.user.dto.UserResponse;
import org.springframework.security.core.Authentication;

public interface AuthService {

	UserResponse register(RegisterRequest registerRequest);

	UserResponse findMe(Authentication authentication);

	UserResponse updateMeBasicInfo(Authentication authentication, UserBasicInfoRequest userBasicInfoRequest);

	void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest);

	void isNotAuthenticated(Authentication authentication);



}
