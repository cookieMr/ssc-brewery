package guru.sfg.brewery.config;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;
import com.warrenstrange.googleauth.ICredentialRepository;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import guru.sfg.brewery.security.BreweryPasswordEncoderFactories;
import guru.sfg.brewery.security.google.Google2faFilter;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String[] PUBLIC_URLS =
            {"/", "/login", "/beers/find", "/webjars/**", "/resources/**"};

    private final UserDetailsService userDetailsService;
    private final PersistentTokenRepository persistentTokenRepository;
    private final Google2faFilter google2faFilter;

    /**
     * This bean is needed for SPeL.
     *
     * @return security evaluation context extension
     */
    @Bean
    public @NotNull SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    @Bean
    public @NotNull PasswordEncoder passwordEncoder() {
        return BreweryPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(@NotNull HttpSecurity http) throws Exception {
        http.addFilterBefore(google2faFilter, SessionManagementFilter.class)
                .csrf().ignoringAntMatchers("/h2-console/**", "/api/**")
                .and()
                .authorizeRequests(authorize ->
                        authorize.mvcMatchers(PUBLIC_URLS).permitAll()
                                .mvcMatchers("/h2-console/**").permitAll()) //do not use in production!
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin(loginConfigure -> loginConfigure.loginProcessingUrl("/login")
                        .loginPage("/").permitAll()
                        .successForwardUrl("/")
                        .defaultSuccessUrl("/")
                        .failureUrl("/?error"))
                .logout(logoutConfigure ->
                        logoutConfigure.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                                .logoutSuccessUrl("/?logout").permitAll())
                .httpBasic()
                .and()
                .rememberMe().tokenRepository(persistentTokenRepository).userDetailsService(userDetailsService)
                .and()
                .headers().frameOptions().sameOrigin();
    }

    @Bean
    public @NotNull AuthenticationEventPublisher authenticationEventPublisher(
            @NotNull ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    public @NotNull IGoogleAuthenticator googleAuthenticator(@NotNull ICredentialRepository repository) {
        GoogleAuthenticatorConfigBuilder configBuilder = new GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(60))
                .setWindowSize(3)
                .setNumberOfScratchCodes(0);

        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(configBuilder.build());
        googleAuthenticator.setCredentialRepository(repository);
        return googleAuthenticator;
    }

}
