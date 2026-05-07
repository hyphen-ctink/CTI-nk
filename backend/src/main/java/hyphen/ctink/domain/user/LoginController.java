package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.LoginRequestDTO;
import hyphen.ctink.domain.user.dto.LoginResponseDTO;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/auth/login")
public class LoginController {

    private final LoginService loginService;

    @PostMapping
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO req, HttpSession session) {
        return ResponseEntity.ok(loginService.loginUser(req, session));
    }
}
