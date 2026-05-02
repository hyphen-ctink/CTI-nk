package hyphen.ctink.domain.log.notification.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.enums.RuleType;

import java.time.LocalDateTime;

public record RuleNotificationLogDTO(
        Long ruleId,
        String ruleName,
        RuleType ruleType,
        AttackType attackType,
        TrustLevel trustLevel,
        LocalDateTime createdAt
) {}
