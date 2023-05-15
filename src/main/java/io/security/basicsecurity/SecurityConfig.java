package io.security.basicsecurity;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );

        http.formLogin()
            //.loginPage("/loginPage")
            .defaultSuccessUrl("/")
            .failureUrl("/login")
            .usernameParameter("userId")
            .passwordParameter("passwd")
            .loginProcessingUrl("/login_proc")
            // .successHandler(new AuthenticationSuccessHandler() {
            //     @Override
            //     public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            //         Authentication authentication) throws IOException, ServletException {
            //         //Authentication : 인증에 성공했을 때 최종적으로 그 인증의 결과를 담은 인증 객체
            //
            //         System.out.println("authentication : " + authentication.getName()); //인증에 성공한 사용자 이름
            //
            //         response.sendRedirect("/");
            //         //인증에 성공하고 root페이지로 이동
            //         // 여기서 successHandler가 정의되면 .defaultSuccessUrl("/") 은 작동을 안한다.
            //     }
            // })
            // .failureHandler(new AuthenticationFailureHandler() {
            //     @Override
            //     public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            //         AuthenticationException exception) throws IOException, ServletException {
            //         //AuthenticationException : 인증 예외의 객체
            //
            //         System.out.println("exception : " + exception.getMessage());
            //
            //         response.sendRedirect("/login");
            //     }
            // })
            .permitAll()
        ;

        http
            .logout()
            .logoutUrl("/logout") // default 는 "logout"이다. spring security 의 logout 처리는 post 방식으로 처리된다.
            .logoutSuccessUrl("/login") // 로그아웃 성공 시 이동할 페이지만 알려줌
            .addLogoutHandler(new LogoutHandler() {
                @Override
                public void logout(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) {
                    HttpSession session = request.getSession();
                    session.invalidate(); //세션 무효화
                }
            })
            .logoutSuccessHandler(new LogoutSuccessHandler() {
                //.logoutSuccessUrl()과 비슷하다. 다만 .logoutSuccessHandler()이 좀 더 다채롭게 구현이 가능하다.
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect("/login");
                }
            })
            .deleteCookies("remember-me") //서버에서 만든 쿠키를 삭제
        ;

        http
            .rememberMe()
            .rememberMeParameter("remember")
            .tokenValiditySeconds(3600)
            .userDetailsService(userDetailsService)
        ;
        return http.build();
    }
}
