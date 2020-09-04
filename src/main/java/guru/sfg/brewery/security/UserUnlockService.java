package guru.sfg.brewery.security;

import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Collection;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserUnlockService {

    private final UserRepository userRepository;

    @Scheduled(fixedRate = 300_000)
    public void unlockAccounts() {
        log.debug("Running unlock account service.");

        Collection<User> lockedUsers = userRepository.findAllByAccountNonLockedAndLastModifiedDateBefore(
                false, Timestamp.valueOf(LocalDateTime.now().minusSeconds(30)));

        if (lockedUsers.isEmpty()) {
            return;
        }

        log.debug("Found {} locked accounts.", lockedUsers.size());
        lockedUsers.forEach(user -> user.setAccountNonLocked(true));
        userRepository.saveAll(lockedUsers);
    }

}
