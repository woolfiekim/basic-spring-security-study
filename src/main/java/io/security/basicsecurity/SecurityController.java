package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session){

        //인증객체1 (SecurityContextHolder 사용)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //인증객체2 (Session 사용)
        SecurityContext context = (SecurityContext)session.getAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        /*
         * 인증객체1과 2는 동일한 객체이다.
         */

        return "home";
    }

    @GetMapping("/thread")
    public String thread(){
        //자식 스레드이기 때문에 값이 null이다.
        new Thread(
            () -> {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            }
        ).start();

        return "thread";
    }
}
