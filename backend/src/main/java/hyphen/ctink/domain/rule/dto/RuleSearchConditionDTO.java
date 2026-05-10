package hyphen.ctink.domain.rule.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;

import java.time.LocalDateTime;

public record RuleSearchConditionDTO(
        String search,
        RuleType ruleType,
        AttackType attackType,
        TrustLevel trustLevel,
        RuleStatus status,
        LocalDateTime dateFrom,
        LocalDateTime dateTo
) {}
