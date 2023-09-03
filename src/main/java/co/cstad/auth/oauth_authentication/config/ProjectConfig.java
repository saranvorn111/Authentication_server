package co.cstad.auth.oauth_authentication.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;


@SuppressWarnings("uncheck")
@Configuration
public class ProjectConfig {

//    @SneakyThrows
    @Bean
    @Order(1)
    public SecurityFilterChain asFilterChain(HttpSecurity http) throws  Exception{

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http.exceptionHandling(
                c-> c.defaultAuthenticationEntryPointFor(
                      new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        return http.build();
    }
    @Bean
    @Order(2)
    public SecurityFilterChain appFilterChain(HttpSecurity http) throws  Exception{

        http.formLogin(Customizer.withDefaults());

        http.authorizeHttpRequests(
                c->c.anyRequest().authenticated()
        );
        return http.build();
    }
    // Create UserServiceDetail
    @Bean
    public UserDetailsService userDetailsService (){

        var viewer = User.withUsername("saran")
                .password("password")
                .authorities("read")
                .roles("VIEWER")
                .build();

        var admin = User.withUsername("faa")
                .password("password")
                .authorities("read")
                .roles("VIEWER","ADMIN")
                .build();

        return new InMemoryUserDetailsManager(viewer , admin);
    }
    @Bean
    public PasswordEncoder passwordEncoder(){

        return NoOpPasswordEncoder.getInstance();
    }
    // Create Registered Client
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client-react-app")
                .tokenSettings(tokenSettings())
                .clientSecret("secret") // it's store manager in secret
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://127.0.0.1:8083/login/oauth2/code/public-client-react-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantType -> {
                    grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
                    grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                }).clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    // Create AuthorizationServerSetting
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();

    }
    // Create JWTSource
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        // create key pair

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);

        var keys = keyPairGenerator.generateKeyPair();

        // create public key and private key

        var publicKey = (RSAPublicKey) keys.getPublic();

        var privateKey = (RSAPrivateKey) keys.getPrivate();


       RSAKey rsaKey = new RSAKey.Builder(publicKey)

                .privateKey(privateKey)

                .keyID(UUID.randomUUID().toString())

                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }
    // create jwt decoder
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {

        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
    // Customize OAuth2 Token
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtEncodingContextOAuth2TokenCustomizer() {

        return context -> {

            if (context.getTokenType().getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue())) {

                Authentication principal = context.getPrincipal();

                var authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)

                        .collect(Collectors.toSet());

                context.getClaims().claim("authorities", authorities);

            }

        };
    }
    @Bean
    public TokenSettings tokenSettings(){
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(2)) // token expiration 2 hours
                .build();

    }
}
