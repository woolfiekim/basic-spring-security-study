package io.security.basicsecurity;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.NoArgsConstructor;

@Configuration
@EnableWebSecurity
@NoArgsConstructor
public class SecurityConfig {

    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain fileterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth ->
                auth
                    .requestMatchers("/login").permitAll()
                    .anyRequest().authenticated()
            );

        http
            .formLogin();

        // http
        //     .logout(form ->
        //         form
        //             .logoutUrl("/logout")
        //             .logoutSuccessUrl("/login?logout")
        //             .addLogoutHandler((request, response, authentication) -> {
        //                 HttpSession session = request.getSession();
        //                 session.invalidate();
        //             })
        //             .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
        //             .deleteCookies("remember-me")
        //     );

        // http
        //     .rememberMe(form ->
        //         form
        //             .userDetailsService(userDetailsService)
        //     );

        http
            .sessionManagement(form ->
                form
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(true)
            );

        // http
        //     .sessionManagement(form ->
        //         form
        //             .sessionFixation()
        //             .changeSessionId()
        //     );

        return http.build();
    }
}
