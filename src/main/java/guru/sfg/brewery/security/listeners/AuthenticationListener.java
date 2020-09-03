package guru.sfg.brewery.security.listeners;

import guru.sfg.brewery.domain.security.LoginFailure;
import guru.sfg.brewery.domain.security.LoginSuccess;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.LoginFailureRepository;
import guru.sfg.brewery.repositories.security.LoginSuccessRepository;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Slf4j
@RequiredArgsConstructor
@Component
public class AuthenticationListener {

    private final LoginFailureRepository loginFailureRepository;
    private final LoginSuccessRepository loginSuccessRepository;
    private final UserRepository userRepository;

    @EventListener
    public void listenForSuccess(@NotNull AuthenticationSuccessEvent event) {
        log.debug("User has successfully logged in.");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) event.getSource();
            LoginSuccess.LoginSuccessBuilder builder = LoginSuccess.builder();

            if (token.getPrincipal() instanceof User) {
                User user = (User) token.getPrincipal();
                builder.user(user);
                log.debug("User name logged in: {}", user.getUsername());
            }

            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                builder.sourceIp(details.getRemoteAddress());
                log.debug("Source IP: " + details.getRemoteAddress());
            }

            LoginSuccess loginSuccess = loginSuccessRepository.save(builder.build());
            log.debug("Login Success saved with ID: {}", loginSuccess.getId());
        }
    }

    @EventListener
    public void listenForBadCredentials(@NotNull AuthenticationFailureBadCredentialsEvent event) {
        log.debug("User failed to log in.");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) event.getSource();
            LoginFailure.LoginFailureBuilder builder = LoginFailure.builder();

            if (token.getPrincipal() instanceof String) {
                String username = (String) token.getPrincipal();
                builder.username(username);
                userRepository.findByUsername(username)
                        .ifPresent(builder::user);
                log.debug("Login failed for user: {}", username);
            }

            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                builder.sourceIp(details.getRemoteAddress());
                log.debug("Source IP: {}", details.getRemoteAddress());
            }

            LoginFailure loginFailure = loginFailureRepository.save(builder.build());
            log.debug("Login Failure saved with ID: {}", loginFailure.getId());

            if (loginFailure.getUser() != null) {
                lockUserAccount(loginFailure.getUser());
            }
        }
    }

    private void lockUserAccount(@NotNull User user) {
        int failedAttempts = loginFailureRepository.findAllByUserAndCreatedDateAfter(
                user, Timestamp.valueOf(LocalDateTime.now().minusDays(1)))
                .size();

        if (failedAttempts > 2) {
            log.debug("Locking account for user: {}", user.getUsername());
            user.setAccountNonLocked(false);
            userRepository.save(user);
        }
    }

}
