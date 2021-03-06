package guru.sfg.brewery.repositories.security;

import guru.sfg.brewery.domain.security.User;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;

import java.sql.Timestamp;
import java.util.Collection;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUsername(String username);

    @NotNull Collection<User> findAllByAccountNonLockedAndLastModifiedDateBefore(
            boolean locked,
            @NotNull Timestamp timestamp);

}
