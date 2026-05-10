package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.admin.dto.DecisionRequestDTO;
import hyphen.ctink.domain.log.notification.enums.Decision;
import hyphen.ctink.domain.user.User;
import hyphen.ctink.domain.user.UserRepository;
import hyphen.ctink.domain.user.enums.UserStatus;
import hyphen.ctink.exception.ConflictException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinDecisionService {
    private  final UserRepository userRepository;

    @Transactional
    public Decision decideJoin(Long userId, DecisionRequestDTO req) {
        User user = userRepository.findById(userId)
                .orElseThrow();

        if (user.getUserStatus() != UserStatus.PENDING) {
            throw new ConflictException("이미 처리된 사용자입니다.");
        }

        Decision decision = req.getDecision();

        if (decision == Decision.APPROVED) {
            user.updateStatus(UserStatus.ACTIVE);
        } else {
            user.updateStatus(UserStatus.INACTIVE);
        }

        return decision;
    }
}
