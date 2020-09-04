package guru.sfg.brewery.security.google;

import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.web.controllers.UserController;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class Google2faFilter extends GenericFilterBean {

    private final AuthenticationTrustResolver authResolver = new AuthenticationTrustResolverImpl();
    private final AuthenticationFailureHandler google2faFailureHandler = new Google2faFailureHandler();
    private final RequestMatcher url2fa = new AntPathRequestMatcher(UserController.USER_VERIFY_2FA_URL);
    private final RequestMatcher urlResources = new AntPathRequestMatcher("/resources/**");

    @Override
    public void doFilter(
            @NotNull ServletRequest request,
            @NotNull ServletResponse response,
            @NotNull FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (url2fa.matches(httpRequest)
                || urlResources.matches(httpRequest)
                || PathRequest.toStaticResources().atCommonLocations().matches(httpRequest)) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && !authResolver.isAnonymous(authentication)) {
            log.debug("Processing 2FA Filter.");

            if (authentication.getPrincipal() instanceof User) {
                User user = (User) authentication.getPrincipal();

                if (user.getUseGoogle2fa() && user.getGoogle2faRequired()) {
                    log.debug("2FA is required.");
                    google2faFailureHandler.onAuthenticationFailure(httpRequest, httpResponse, null);

                    return;
                }
            }
        }

        chain.doFilter(httpRequest, httpResponse);
    }

}
