package guru.sfg.brewery.security;

import org.jetbrains.annotations.NotNull;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class RestHeaderAuthenticationFilter extends AbstractRestAuthenticationFilter {

    public RestHeaderAuthenticationFilter(@NotNull RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    protected @NotNull String getUsername(@NotNull HttpServletRequest request) {
        String username = request.getHeader("api-key");
        return username == null ? "" : username;
    }

    @Override
    protected @NotNull String getPassword(@NotNull HttpServletRequest request) {
        String password = request.getHeader("api-secret");
        return password == null ? "" : password;
    }

}
