package guru.sfg.brewery.web.controllers;

import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Objects;
import java.util.Optional;

@Slf4j
@RequestMapping("/user")
@RequiredArgsConstructor
@Controller
public class UserController {

    public static final String USER_REGISTER_2FA_URL = "/user/register2fa";
    public static final String USER_VERIFY_2FA_URL = "/user/verify2fa";

    private final IGoogleAuthenticator googleAuthenticator;
    private final UserRepository userRepository;

    @Value("${spring.application.name:@null}")
    private String appName;

    @GetMapping("register2fa")
    public @NotNull String register2fa(@NotNull Model model) {
        String username = getUserFromPrincipal().getUsername();

        String url = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                Objects.requireNonNull(appName),
                username,
                googleAuthenticator.createCredentials(username));
        log.debug("Google QR URL: {}", url);

        model.addAttribute("googleUrl", url);
        return USER_REGISTER_2FA_URL;
    }

    @PostMapping("register2fa")
    public @NotNull String confirm2fa(@Nullable @RequestParam Integer verifyCode) {
        if (verifyCode == null) {
            return USER_REGISTER_2FA_URL;
        }

        User user = getUserFromPrincipal();
        log.debug("User {} entered confirmation code {}.", user.getUsername(), verifyCode);

        if (googleAuthenticator.authorizeUser(user.getUsername(), verifyCode)) {
            User userToSave = userRepository.findById(user.getId()).orElseThrow();
            userToSave.setUseGoogle2fa(true);
            userRepository.save(userToSave);

            return "index";
        } else {
            return USER_REGISTER_2FA_URL;
        }
    }

    @GetMapping("/verify2fa")
    public @NotNull String verify2fa() {
        return USER_VERIFY_2FA_URL;
    }

    @PostMapping("/verify2fa")
    public @NotNull String verifyPost2fa(@Nullable @RequestParam Integer verifyCode) {
        if (verifyCode == null) {
            return USER_VERIFY_2FA_URL;
        }

        User user = getUserFromPrincipal();
        log.debug("User {} entered verification code {}.", user.getUsername(), verifyCode);

        if (googleAuthenticator.authorizeUser(user.getUsername(), verifyCode)) {
            user.setGoogle2faRequired(false);

            return "index";
        } else {
            return USER_VERIFY_2FA_URL;
        }
    }

    private @NotNull User getUserFromPrincipal() {
        return Optional.of(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .map(Authentication::getPrincipal)
                .map(User.class::cast)
                .orElseThrow();
    }

}
