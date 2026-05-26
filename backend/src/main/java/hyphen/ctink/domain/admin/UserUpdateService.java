package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.admin.dto.UserUpdateRequestDTO;
import hyphen.ctink.domain.user.User;
import hyphen.ctink.domain.user.UserRepository;
import hyphen.ctink.domain.user.enums.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserUpdateService {

    private final UserRepository userRepository;

    @Transactional
    public String userUpdate(UserUpdateRequestDTO req, String loginId) {
        User user = userRepository.findByLoginId(loginId)
                .orElseThrow(() ->
                        new IllegalArgumentException("존재하지 않는 사용자입니다."));

        if (req.role() != null) {
            user.updateRole(req.role());
        }

        if (req.status() != null) {
            if (user.getUserStatus() == UserStatus.PENDING) {
                return "pending";
            }

            switch (req.status()) {
                case LOCKED -> {
                    return "locked";
                }

                case ACTIVE -> {
                    user.updateStatus(req.status());
                    user.updateLoginAttempts();
                }

                case INACTIVE, PENDING -> {
                    user.updateStatus(req.status());
                }
            }
        }

        return "사용자 정보가 수정되었습니다";
    }
}
