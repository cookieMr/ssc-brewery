package guru.sfg.brewery.repositories.security;

import guru.sfg.brewery.domain.security.LoginFailure;
import guru.sfg.brewery.domain.security.User;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;

import java.sql.Timestamp;
import java.util.Collection;

public interface LoginFailureRepository extends JpaRepository<LoginFailure, Integer> {

    @NotNull Collection<LoginFailure> findAllByUserAndCreatedDateAfter(
            @NotNull User user,
            @NotNull Timestamp timestamp);

}
