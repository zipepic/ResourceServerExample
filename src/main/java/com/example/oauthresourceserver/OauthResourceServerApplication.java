package com.example.oauthresourceserver;

import com.project.core.dto.UserProfileDTO;
import com.project.core.queries.FetchJwksQuery;
import com.project.core.queries.user.FetchUserProfileDTOByUserIdQuery;
import com.project.core.queries.user.FindUserIdByUserNameAndValidatePasswordQuery;
import com.thoughtworks.xstream.XStream;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import tokenlib.util.jwk.SimpleJWK;

@SpringBootApplication
@EnableWebSecurity
public class OauthResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthResourceServerApplication.class, args);
    }

    @Bean
    public XStream xStream() {
        XStream xStream = new XStream();
        registerClasses(xStream,
                SimpleJWK.class,
                FetchJwksQuery.class,
                UserProfileDTO.class,
                FetchUserProfileDTOByUserIdQuery.FetchUserProfileDTOByUserIdQueryBuilder.class,
                FindUserIdByUserNameAndValidatePasswordQuery.class);

        return xStream;
    }

    private void registerClasses(XStream xStream, Class<?>... classes) {
        for (Class<?> clazz : classes) {
            xStream.allowTypeHierarchy(clazz);
        }
    }

}
