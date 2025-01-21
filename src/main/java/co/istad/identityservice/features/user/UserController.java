package co.istad.identityservice.features.user;

import co.istad.identityservice.features.user.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @PutMapping("/{username}")
    UserResponse update(@PathVariable String username, @Valid @RequestBody UserBasicInfoRequest userBasicInfoRequest) {
        return userService.updateBasicInfo(username, userBasicInfoRequest);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @PutMapping("/{username}/reset-password")
    UserPasswordResetResponse resetPassword(@PathVariable String username) {
        return userService.resetPassword(username);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{username}/disable")
    void disable(@PathVariable String username) {
        userService.disable(username);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{username}/enable")
    void enable(@PathVariable String username) {
        userService.enable(username);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    void createNew(@Valid @RequestBody UserCreateRequest userCreateRequest) {
        userService.createNewUser(userCreateRequest);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @GetMapping
    Page<UserResponse> findList(@RequestParam(required = false, defaultValue = "0") int pageNumber,
                                @RequestParam(required = false, defaultValue = "25") int pageSize) {
        return userService.findList(pageNumber, pageSize);
    }


    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    @GetMapping("/{username}")
    UserResponse findByUsername(@PathVariable String username) {
        return userService.findByUsername(username);
    }


}
