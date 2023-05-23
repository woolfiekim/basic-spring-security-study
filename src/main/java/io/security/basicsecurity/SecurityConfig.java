package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig {
    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {

        http.securityMatcher("/admin/**");

        http
            .authorizeHttpRequests(
                requests ->
                    requests
                        // .requestMatchers("/admin/**").permitAll()
                        // .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated()
            );

        http
            .httpBasic();

        return http.build();
    }

}

@Configuration
@Order(1)
class SecurityConfig2 {

    @Bean
    public SecurityFilterChain globalFilterChain2(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth ->
                auth.anyRequest().permitAll()
            );

        http.formLogin(Customizer.withDefaults());

        return http.build();
    }
}