package guru.sfg.brewery.security.google;

import guru.sfg.brewery.web.controllers.UserController;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class Google2faFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @Nullable AuthenticationException exception) throws IOException, ServletException {
        log.debug("Forward to 2FA.");
        request.getRequestDispatcher(UserController.USER_VERIFY_2FA_URL)
                .forward(request, response);
    }

}
