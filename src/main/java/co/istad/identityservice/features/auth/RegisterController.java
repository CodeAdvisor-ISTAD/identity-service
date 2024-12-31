package co.istad.identityservice.features.auth;

import co.istad.identityservice.domain.User;
import co.istad.identityservice.features.auth.dto.*;
import co.istad.identityservice.features.emailverification.EmailVerificationTokenService;
import co.istad.identityservice.features.emailverification.dto.EmailVerifyRequest;
import co.istad.identityservice.features.user.UserRepository;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@Controller
@RequiredArgsConstructor
@Slf4j
//@SuppressWarnings({"unused"})
public class RegisterController {

    private final AuthService authService;
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final UserRepository userRepository;


    @GetMapping("/forget-password")
    public String showForgetPasswordForm(Model model) {
        model.addAttribute("forgetPasswordRequest", new ForgetPasswordRequest());
        return "forget-password";
    }

    @PostMapping("/forget-password")
    public String handleForgetPassword(
            @Valid @ModelAttribute("forgetPasswordRequest") ForgetPasswordRequest forgetPasswordRequest,
            BindingResult result,
            HttpSession session,
            Model model) {

        log.info("email: {}", forgetPasswordRequest.getEmail());

        if (result.hasErrors()) {
            return "forget-password";
        }

        try {
            String registrationResult = authService.forgetPassword(forgetPasswordRequest.getEmail());

            if (registrationResult.equals("Email is not in the system")) {
                model.addAttribute("emailError", registrationResult);
                return "forget-password";
            } else {
                session.setAttribute("username", registrationResult);
                log.info("username forget: {}", registrationResult);
                return "redirect:/reset-pwd-otp";
            }
        } catch (Exception e) {
            model.addAttribute("globalError", "An unexpected error occurred");
            return "forget-password";
        }
    }

    @GetMapping("/reset-pwd-otp")
    public String showResetPwdOtpForm(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        if (username == null) {
            return "redirect:/forget-password";
        }
        model.addAttribute("emailVerifyRequest", new EmailVerifyRequest(username, ""));
        model.addAttribute("userName", username);
        return "reset-pwd-otp";
    }


    @PostMapping("/reset-pwd-otp")
    public String handleResetPwdOtp(@Valid @ModelAttribute("otpRequest") EmailVerifyRequest emailVerifyRequest,
                                    BindingResult result,
                                    Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        model.addAttribute("userName", username);

        log.info("result has errors: {}", result.getModel());


        if (result.hasErrors()) {
            model.addAttribute("error", "Invalid OTP or Username. Please try again.");
            return "reset-pwd-otp";
        }

        try {
            emailVerificationTokenService.verify(emailVerifyRequest);
            model.addAttribute("successMessage", "OTP verified successfully!");
            return "redirect:/reset-password";
        } catch (Exception e) {
            model.addAttribute("error", "OTP verification failed. Please try again.");
            return "reset-pwd-otp";
        }
    }


    @GetMapping("/reset-password")
    public String showResetPasswordForm(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        if (username == null) {
            return "redirect:/forget-password";
        }
        model.addAttribute("resetPasswordRequest", new ResetPasswordRequest(username, "", ""));
        model.addAttribute("userName", username);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(
            @Valid @ModelAttribute("resetPasswordRequest") ResetPasswordRequest resetPasswordRequest,
            BindingResult result,
            Model model,
            HttpSession session) {

        String username = (String) session.getAttribute("username");
        model.addAttribute("userName", username);

        log.info("result has errors reset-password: {}", result.hasErrors());

        // Check for validation errors
        if (result.hasErrors()) {
            return "reset-password";
        }

        // Additional password validation
        if (!resetPasswordRequest.password().equals(resetPasswordRequest.confirmPassword())) {
            result.rejectValue("confirmPassword", "error.confirmPassword", "Passwords do not match");
            return "reset-password";
        }

        try {
            authService.resetPassword(resetPasswordRequest);
            return "redirect:/login";
        } catch (Exception e) {
            model.addAttribute("error", "Password reset failed. Please try again.");
            return "reset-password";
        }
    }



    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest("", "", "", "", ""));
        return "register";
    }

    @PostMapping("/register")
    public String handleRegistration(@Valid @ModelAttribute("registerRequest") RegisterRequest registerRequest,
                                     BindingResult result, Model model, HttpSession session) {
        result.getAllErrors().forEach(error -> {
            log.info("error: {}", error.getDefaultMessage());
        });

        if (result.hasErrors()) {
            return "register";
        }
        log.info("Register request: {}", registerRequest);


        // Handle successful registration logic (e.g., saving the user)
        String registrationResult = authService.register(registerRequest);
        // Check if registration was successful
        if (registrationResult.equals("Account created successfully!")) {
            // Save the username in the session
            session.setAttribute("username", registerRequest.username());
            return "redirect:/otp";
        } else {
            // If there's an error message (username or email taken)
            if (registrationResult.equals("Username is already taken")) {
                result.rejectValue("username", "error.username", registrationResult);
            } else if (registrationResult.equals("Email is already taken")) {
                result.rejectValue("email", "error.email", registrationResult);
            }
            return "register";
        }

    }

    @GetMapping("/otp")
    public String showOtpForm(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        if (username == null) {
            return "redirect:/register";
        }
        model.addAttribute("emailVerifyRequest", new EmailVerifyRequest(username, ""));
        model.addAttribute("userName", username);
        return "otp";
    }

    @PostMapping("/otp")
    public String handleOtp(@Valid @ModelAttribute("emailVerifyRequest") EmailVerifyRequest emailVerifyRequest,
                            BindingResult result,
                            Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        model.addAttribute("userName", username);



        log.info("result has errors: {}", result.getModel());


        if (result.hasErrors()) {
            model.addAttribute("error", "Invalid OTP or Username. Please try again.");
            return "otp";
        }

        try {
            emailVerificationTokenService.verify(emailVerifyRequest);
            model.addAttribute("successMessage", "OTP verified successfully!");
            User user = userRepository.findByUsername(username).orElse(null);
            assert user != null;

            Object userCreated = UserCreatedEvent.builder()
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .fullName(user.getFullName())
                    .uuid(user.getUuid())
                    .profileImage(user.getProfileImage())
                    .build();

            kafkaTemplate.send("user-created-events-topic", String.valueOf(user.getId()), userCreated );
            log.info("User created event sent to Kafka");
            return "redirect:/login";
        } catch (Exception e) {
            model.addAttribute("error", "OTP verification failed. Please try again.");
            return "otp";
        }
    }

    @PostMapping("/resend-otp")
    public String resendOtp(Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        log.info("username resend : {}", username);

        try {
            emailVerificationTokenService.resend(username);
            model.addAttribute("successMessage", "OTP sent successfully!");
            return "redirect:/otp";
        } catch (Exception e) {
            model.addAttribute("error", "OTP sending failed. Please try again.");
            return "otp";
        }
    }


}
