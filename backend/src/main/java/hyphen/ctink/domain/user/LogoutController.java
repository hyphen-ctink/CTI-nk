package hyphen.ctink.domain.user;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
@RequestMapping("/ctink/auth/logout")
public class LogoutController {

    private final LogoutService logoutService;

    @PostMapping
    public ResponseEntity<String> logout(HttpSession session) {
        logoutService.logout(session);
        return ResponseEntity.ok("로그아웃 되었습니다.");
    }
}
