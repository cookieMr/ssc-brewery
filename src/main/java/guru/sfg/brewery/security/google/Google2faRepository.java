package guru.sfg.brewery.security.google;

import com.warrenstrange.googleauth.ICredentialRepository;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Slf4j
@Component
public class Google2faRepository implements ICredentialRepository {

    private final UserRepository userRepository;

    @Override
    public @NotNull String getSecretKey(@NotNull String userName) {
        return userRepository.findByUsername(userName)
                .map(User::getGoogle2faSecret)
                .orElseThrow();
    }

    @Override
    public void saveUserCredentials(
            @NotNull String userName,
            @NotNull String secretKey,
            int validationCode,
            @Nullable List<Integer> scratchCodes) {
        User user = userRepository.findByUsername(userName).orElseThrow();
        user.setGoogle2faSecret(secretKey);
        user.setGoogle2faRequired(true);
        userRepository.save(user);
    }

}
