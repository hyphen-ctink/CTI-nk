package hyphen.ctink.domain.log.notification.dto;

import hyphen.ctink.domain.rule.enums.RuleType;

public record RuleNotificationRequestDTO(
    Integer page,
    RuleType ruleType
) {}
