package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.LoginRequestDTO;
import hyphen.ctink.domain.user.dto.LoginResponseDTO;
import hyphen.ctink.domain.user.enums.UserStatus;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public LoginResponseDTO loginUser(LoginRequestDTO req, HttpSession session) {
        User user = userRepository.findByLoginId(req.loginId())
                .orElseThrow(() ->
                        new IllegalArgumentException("아이디 또는 비밀번호가 일치하지 않습니다."));

        switch (user.getUserStatus()) {
            case INACTIVE -> {
                return new LoginResponseDTO(
                        "비활성화된 계정입니다.",
                        null,
                        null,
                        null
                );
            }

            case PENDING -> {
                return new LoginResponseDTO(
                        "관리자 승인 대기 중인 계정입니다.",
                        null,
                        null,
                        null
                );
            }

            case LOCKED -> {
                return new LoginResponseDTO(
                        "로그인 5회 실패로 계정이 잠금되었습니다.",
                        null,
                        null,
                        null
                );
            }
        }

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            user.increaseLoginAttempts();

            int loginAttempts = user.getLoginAttempts();

            if (loginAttempts >= 5) {
                user.setUserStatus(UserStatus.LOCKED);

                return new LoginResponseDTO(
                        "로그인 5회 실패로 계정이 잠금되었습니다.",
                        null,
                        null,
                        null
                );
            } else if (loginAttempts >= 3) {
                return new LoginResponseDTO(
                        "5회 실패 시 계정이 잠깁니다. 기억이 나지 않으신다면 관리자에게 미리 문의해 주세요.",
                        null,
                        null,
                        null
                );
            }

            return new LoginResponseDTO(
                    "아이디 또는 비밀번호가 일치하지 않습니다.",
                    null,
                    null,
                    null
            );
        }

        user.saveLastLoginAt();
        session.setAttribute("LOGIN_USER", user.getId());
        session.setAttribute("LOGIN_ROLE", user.getRole());

        return new LoginResponseDTO(
                null,
                user.getRole(),
                user.getName(),
                user.getLoginAttempts()
        );
    }
}
