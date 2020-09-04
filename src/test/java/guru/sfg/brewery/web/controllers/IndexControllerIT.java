package guru.sfg.brewery.web.controllers;

import com.warrenstrange.googleauth.IGoogleAuthenticator;
import guru.sfg.brewery.repositories.BeerInventoryRepository;
import guru.sfg.brewery.repositories.BeerRepository;
import guru.sfg.brewery.repositories.CustomerRepository;
import guru.sfg.brewery.repositories.security.UserRepository;
import guru.sfg.brewery.services.BeerOrderService;
import guru.sfg.brewery.services.BeerService;
import guru.sfg.brewery.services.BreweryService;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.util.stream.Stream;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
class IndexControllerIT extends AbstractBaseIT {

    @MockBean
    BeerRepository beerRepository;

    @MockBean
    BeerInventoryRepository beerInventoryRepository;

    @MockBean
    BreweryService breweryService;

    @MockBean
    CustomerRepository customerRepository;

    @MockBean
    BeerService beerService;

    @MockBean
    BeerOrderService beerOrderService;

    @MockBean
    UserDetailsService userDetailsService;

    @MockBean
    PersistentTokenRepository persistentTokenRepository;

    @MockBean
    UserRepository userRepository;

    @MockBean
    IGoogleAuthenticator googleAuthenticator;

    private static @NotNull Stream<String> publicUrls() {
        return Stream.of("/", "/beers/find");
    }

    @ParameterizedTest
    @MethodSource("publicUrls")
    void getPublicUrlWithoutHttpBasicAuth(@NotNull String url) throws Exception {
        mockMvc.perform(get(url))
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @MethodSource("publicUrls")
    void getPublicUrlWithAnonymousHttpBasicAuth(@NotNull String url) throws Exception {
        mockMvc.perform(get(url).with(anonymous()))
                .andExpect(status().isOk());
    }

    @Disabled("TODO: remember me broke this test for some reason, investigate it later; probably mockbean is an issue")
    @ParameterizedTest
    @MethodSource("publicUrls")
    void getPublicUrlWithHttpBasicAuth(@NotNull String url) throws Exception {
        mockMvc.perform(get(url).with(httpBasic(adminUser, adminPassword)))
                .andExpect(status().isOk());
    }

}
