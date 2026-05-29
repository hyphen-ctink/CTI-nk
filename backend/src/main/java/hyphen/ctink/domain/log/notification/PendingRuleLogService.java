package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class PendingRuleLogService {

    private final NotificationLogRepository notificationLogRepository;

    public void pendingRuleLog(DetectionRule rule) {
        if (rule.getTrustLevel() == TrustLevel.LOW && rule.getRuleStatus() == RuleStatus.PENDING) {
            NotificationLog log = NotificationLog.builder()
                    .notificationType(NotificationType.ADMIN_POLICY_REQUEST)
                    .ruleType(rule.getRuleType())
                    .detectionRule(rule)
                    .isSent(false)
                    .createdAt(LocalDateTime.now())
                    .build();

            notificationLogRepository.save(log);
        }
    }
}
