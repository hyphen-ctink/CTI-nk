package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PendingRuleLogService {

    public void pendingRuleLog(DetectionRule rule) {
        if (rule.getTrustLevel() == TrustLevel.LOW && rule.getRuleStatus() == RuleStatus.PENDING) {
            NotificationLog.builder()
                    .notificationType(NotificationType.ADMIN_POLICY_REQUEST)
                    .ruleType(rule.getRuleType())
                    .detectionRule(rule)
                    .isSent(false)
                    .build();
        }
    }
}
