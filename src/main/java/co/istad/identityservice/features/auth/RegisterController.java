package co.istad.identityservice.features.auth;

import co.istad.identityservice.features.auth.dto.OtpRequest;
import co.istad.identityservice.features.auth.dto.RegisterRequest;
import co.istad.identityservice.features.emailverification.EmailVerificationTokenService;
import co.istad.identityservice.features.emailverification.dto.EmailVerifyRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
public class RegisterController {

    private final AuthService authService;
    private final EmailVerificationTokenService emailVerificationTokenService;

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest("", "", "", "", ""));
        return "register";
    }

    @PostMapping("/register")
    public String handleRegistration(@Valid @ModelAttribute("registerRequest") RegisterRequest registerRequest,
                                     BindingResult result, Model model, HttpSession session) {
        if (result.hasErrors()) {
            return "register";
        }
        log.info("Register request: {}", registerRequest);

        // Handle successful registration logic (e.g., saving the user)
        authService.register(registerRequest);

        // Save the username in the session
        session.setAttribute("username", registerRequest.username());

        model.addAttribute("successMessage", "Account created successfully!");
        return "redirect:/otp";
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
                            Model model , HttpSession session) {
        String username = (String) session.getAttribute("username");

        log.info("result has errors: {}", result.getModel());


        if (result.hasErrors()) {
            model.addAttribute("error", "Invalid OTP or Username. Please try again.");
            return "otp";
        }

        try {
            emailVerificationTokenService.verify(emailVerifyRequest);
            model.addAttribute("successMessage", "OTP verified successfully!");
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
            return "redirect:/otp";
        }
    }


}
