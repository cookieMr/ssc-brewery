package guru.sfg.brewery.config;

import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class RememberMeConfiguration {

    @Bean
    public @NotNull PersistentTokenRepository persistentTokenRepository(@NotNull DataSource dataSource) {
        JdbcTokenRepositoryImpl jdbcRepository = new JdbcTokenRepositoryImpl();
        jdbcRepository.setDataSource(dataSource);
        return jdbcRepository;
    }

}
