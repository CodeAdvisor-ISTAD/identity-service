package co.istad.identityservice.features.auth;


import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.auth.dto.ChangePasswordRequest;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.auth.dto.RegisterSubscriberRequest;
import co.istad.identityservice.features.user.UserMapper;
import co.istad.identityservice.features.user.UserRepository;
import co.istad.identityservice.features.user.UserService;
import co.istad.identityservice.features.user.dto.UserBasicInfoRequest;
import co.istad.identityservice.features.user.dto.UserCreateRequest;
import co.istad.identityservice.features.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;


    @Transactional
    @Override
    public UserResponse register(RegisterRequest registerRequest) {

        /*// map register request to user entity (DTO pattern)
        UserCreationRequest userCreationRequest = userMapper.mapRegisterRequestToUserCreationRequest(registerRequest);

        // check if password and confirmation password match (validation)
        userService.checkForPasswords(registerRequest.password(), registerRequest.confirmedPassword());

        // check if accept terms or not (validation)
        userService.checkTermsAndConditions(registerRequest.acceptTerms());

        // if everything is OK, user will be created
        userService.createNewUser(userCreationRequest);

        return userService.findByUsername(registerRequest.username());*/
        return null;
    }

    @Override
    public UserResponse findMe(Authentication authentication) {
        isNotAuthenticated(authentication);
        return userService.findByUsername(authentication.getName());
    }

    @Transactional
    @Override
    public UserResponse updateMeBasicInfo(Authentication authentication, UserBasicInfoRequest userBasicInfoRequest) {

        isNotAuthenticated(authentication);

        // retrieve user by username from db
        User user = userRepository.findByUsernameAndIsEnabledTrue(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        // map user basic info request (DTO) to user (Entity) (partially mapping)
        userMapper.mapUserBasicInfoRequestToUser(userBasicInfoRequest, user);

        // save for updating data
        user = userRepository.save(user);

        // return back UserResponse
        return userMapper.toUserResponse(user);
    }

    @Transactional
    @Override
    public void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest) {

        isNotAuthenticated(authentication);

        userService.checkForPasswords(changePasswordRequest.password(), changePasswordRequest.confirmedPassword());
        userService.checkForOldPassword(authentication.getName(), changePasswordRequest.oldPassword());

        // retrieve user by username from db
        User user = userRepository.findByUsernameAndIsEnabledTrue(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        user.setPassword(passwordEncoder.encode(changePasswordRequest.password()));
        userRepository.save(user);
    }

    @Override
    public void isNotAuthenticated(Authentication authentication) {
        if (authentication == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token is required");
        }
    }

}
