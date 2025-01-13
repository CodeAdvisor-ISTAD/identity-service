package co.istad.identityservice.features.user;


import co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.user.dto.*;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    User mappedFromUpdateUserEvent(UpdateUserEvent updateUserEvent);

    User registerRequestToUser(RegisterRequest registerRequest);

    UserResponse toUserResponse(User user);

    List<UserResponse> toUserResponseList(List<User> users);

    User fromUserCreationRequest(UserCreateRequest userCreateRequest);

    User fromUserBasicInfoRequest(UserBasicInfoRequest userBasicInfoRequest);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
	void mapUserBasicInfoRequestToUser(UserBasicInfoRequest userBasicInfoRequest, @MappingTarget User user);

    UserCreateRequest mapRegisterRequestToUserCreationRequest(RegisterRequest registerRequest);

    UserCreateRequest fromUser(User user);

}
