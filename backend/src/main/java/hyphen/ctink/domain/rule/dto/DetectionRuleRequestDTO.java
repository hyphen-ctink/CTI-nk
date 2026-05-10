package hyphen.ctink.domain.rule.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;

public record DetectionRuleRequestDTO(
    Integer page,
    String search,
    RuleType ruleType,
    AttackType attackType,
    TrustLevel trustLevel,
    RuleStatus status,
    String dateFrom,
    String dateTo
) {}
