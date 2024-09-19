package ru.alishev.springcourse.spingsecuritymyapp1.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import ru.alishev.springcourse.spingsecuritymyapp1.services.PersonDetailsService;
import java.util.Collections;


@Component
public class AuthProviderImpl implements AuthenticationProvider {

    private final PersonDetailsService personDetailsService;

    @Autowired
    public AuthProviderImpl(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }

    // принимает Credentials - логин и пароль, возвращает объект с PersonDetails - человек и все его данные
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        UserDetails personDetails = personDetailsService.loadUserByUsername(username);

        String password = authentication.getCredentials().toString();

        if (!password.equals(personDetails.getPassword())) {
            throw new BadCredentialsException("Incorrect password");
        }

        return new UsernamePasswordAuthenticationToken(personDetails, password,
                Collections.emptyList());
    }

    // метод нужен, чтобы дать Spring понять, для какого объекта он нужен,
    // если AuthProvider будет много
    @Override
    public boolean supports(Class<?> authentication) {
        return true; // метод хорош для всех случаев или прописать, для каких сценариев
        // какой AuthProvider использовать
    }
}
