package co.istad.identityservice.features.user;


import co.istad.identityservice.config.kafka.eventClass.UpdateUserEvent;
import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.user.dto.*;
import org.mapstruct.*;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UpdateUserDto mappedFromUpdateUserEvent(UpdateUserEvent updateUserEvent);

//    @Mapping(target = "dob", source = "dob", qualifiedByName = "stringToLocalDate")
//    @Mapping(target = "uuid", source = "authorUuid")
//    User mappedFromUpdateUserDto(UpdateUserDto updateUserDto);

    User registerRequestToUser(RegisterRequest registerRequest);

    UserResponse toUserResponse(User user);

    List<UserResponse> toUserResponseList(List<User> users);

    User fromUserCreationRequest(UserCreateRequest userCreateRequest);

    User fromUserBasicInfoRequest(UserBasicInfoRequest userBasicInfoRequest);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
	void mapUserBasicInfoRequestToUser(UserBasicInfoRequest userBasicInfoRequest, @MappingTarget User user);

    UserCreateRequest mapRegisterRequestToUserCreationRequest(RegisterRequest registerRequest);

    UserCreateRequest fromUser(User user);

    @Named("stringToLocalDate")
    default LocalDate stringToLocalDate(String dateStr) {
        if (dateStr == null || dateStr.trim().isEmpty()) {
            return null;
        }

        // Common date formats
        DateTimeFormatter[] formatters = {
                DateTimeFormatter.ISO_DATE,  // yyyy-MM-dd
                DateTimeFormatter.ofPattern("MM/dd/yyyy"),
                DateTimeFormatter.ofPattern("dd/MM/yyyy"),
                DateTimeFormatter.ofPattern("yyyy.MM.dd")
        };

        for (DateTimeFormatter formatter : formatters) {
            try {
                return LocalDate.parse(dateStr.trim(), formatter);
            } catch (DateTimeParseException e) {
                continue;
            }
        }

        throw new IllegalArgumentException("Unable to parse date: " + dateStr +
                ". Supported formats are: yyyy-MM-dd, MM/dd/yyyy, dd/MM/yyyy, yyyy.MM.dd");
    }


}
