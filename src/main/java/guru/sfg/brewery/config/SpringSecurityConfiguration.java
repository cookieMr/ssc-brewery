package guru.sfg.brewery.config;

import guru.sfg.brewery.security.BreweryPasswordEncoderFactories;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String[] PUBLIC_URLS =
            {"/", "/login", "/beers/find", "/webjars/**", "/resources/**"};

    private final UserDetailsService userDetailsService;

    /**
     * This bean is needed for SPeL.
     *
     * @return security evaluation context extension
     */
    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    @Bean
    public @NotNull PasswordEncoder passwordEncoder() {
        return BreweryPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(@NotNull HttpSecurity http) throws Exception {
        http.csrf().ignoringAntMatchers("/h2-console/**", "/api/**")
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
                .rememberMe().key("cookieMr").userDetailsService(userDetailsService)
                .and()
                .headers().frameOptions().sameOrigin();
    }

}
