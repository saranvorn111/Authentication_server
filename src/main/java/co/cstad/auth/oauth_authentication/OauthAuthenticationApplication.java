package co.cstad.auth.oauth_authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OauthAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthAuthenticationApplication.class, args);

        System.out.println("Hello world");
    }

}
