package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.log.notification.NotificationLogRepository;
import hyphen.ctink.domain.log.notification.enums.Decision;
import hyphen.ctink.domain.admin.dto.RuleDecisionRequestDTO;
import hyphen.ctink.domain.rule.DetectionRuleRepository;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.exception.ConflictException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class RuleDecisionService {
    private final DetectionRuleRepository detectionRuleRepository;
    private final NotificationLogRepository notificationLogRepository;

    @Transactional
    public Decision decideRule(Long ruleId, RuleDecisionRequestDTO req) {
        DetectionRule rule = detectionRuleRepository.findById(ruleId)
                .orElseThrow();

        // 409
        if (rule.getRuleStatus() != RuleStatus.PENDING) {
            throw new ConflictException("이미 처리된 rule입니다.");
        }

        Decision decision = req.getDecision();

        if (decision == Decision.APPROVED) {
            rule.updateStatus(RuleStatus.ACTIVE);
        } else {
            rule.updateStatus(RuleStatus.INACTIVE);
        }

        notificationLogRepository.updateDecision(
                ruleId,
                decision,
                LocalDateTime.now()
        );

        return decision;
    }
}
