package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.JoinRequestDTO;
import hyphen.ctink.domain.user.enums.Role;
import hyphen.ctink.domain.user.enums.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public String joinUser(JoinRequestDTO req) {
        if (userRepository.existsByLoginId(req.loginId())) {
            return "이미 사용 중인 아이디입니다.";
        }
        if (userRepository.existsByEmail(req.email())) {
            return "이미 사용 중인 이메일입니다.";
        }

        User user = User.builder()
                .loginId(req.loginId())
                .passwordHash(passwordEncoder.encode(req.password()))
                .name(req.name())
                .organization(req.organization())
                .position(req.position())
                .email(req.email())
                .phone(req.phone())
                .role(Role.USER)
                .userStatus(UserStatus.PENDING)
                .loginAttempts(0)
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(user);

        return "회원가입이 완료되었습니다.";
    }
}
