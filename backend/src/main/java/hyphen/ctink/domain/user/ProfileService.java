package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.ProfileResponseDTO;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final UserRepository userRepository;

    public ProfileResponseDTO profile(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");

        if (userId == null) {
            throw new IllegalArgumentException("로그인이 필요합니다.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new IllegalArgumentException("존재하지 않는 사용자입니다."));

        return new ProfileResponseDTO(
                user.getLoginId(),
                user.getName(),
                user.getOrganization(),
                user.getPosition(),
                user.getEmail(),
                user.getPhone(),
                user.getUserStatus(),
                user.getLastLoginAt()
        );
    }
}
