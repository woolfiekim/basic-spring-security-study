package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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
                    .requestMatchers("/").authenticated() //인증된 사용자의 접근을 허용
                    .requestMatchers("/").fullyAuthenticated() //인증된 사용자(ID, PWD로 로그인한 유저)의 접근을 허용, rememberMe 인증 제외
                    .requestMatchers("/").permitAll() //무조건 접근을 허용
                    .requestMatchers("/").denyAll() //무조건 접근을 허용하지 않음
                    .requestMatchers("/").anonymous() //익명사용자("ROLE_Anonymous" 권한을 가진 사용자만)의 접근을 허용
                    .requestMatchers("/").rememberMe() //리멤버미를 통해 인증된 사용자의 접근을 허용
                    .requestMatchers("/").hasRole("USER") //사용자가 주어진 역할이 있다면 접근을 허용 (prefix인 "ROLE_" 이 붙지않은)
                    .requestMatchers("/").hasAuthority("ROLE_USER") //사용자가 주어진 권한이 있다면(prefix인 "ROLE_" 이 붙은)
                    .requestMatchers("/").hasAnyRole("ADMIN", "SYS") //사용자가 주어진 권한이 있다면 접근을 허용(권한 여러 개 가능)
                    .requestMatchers("/").hasAnyAuthority("ROLE_ADMIN", "ROLE_SYS") //사용자가 주어진 권한이 있다면 접근을 허용(권한 여러 개 가능)
            );

        http
            .exceptionHandling(auth ->
                auth
                    .authenticationEntryPoint((request, response, authException) -> {
                        response.sendRedirect("/login ");
                    })
                    .accessDeniedHandler((request, response, accessDeniedException) -> {
                        response.sendRedirect("/denied" );
                    })
            );


        http
            .formLogin()
            .successHandler((request, response, authentication) -> {
                RequestCache requestCache = new HttpSessionRequestCache();
                SavedRequest savedRequest = requestCache.getRequest(request, response);
                String redirectUrl = savedRequest.getRedirectUrl(); //사용자가 원래 가고 싶었던 페이지 경로
                response.sendRedirect(redirectUrl); //인증에 성공하고 나서 바로 그 이전의 정보를 가져와서 바로 이동하도록 처리
            });

        return http.build();
    }


    @Bean
    public void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
        //{noop} : 어떠한 암호화를 했는 지 알려주는 것을 prefix로 붙여주는 것이다.
    }





}
