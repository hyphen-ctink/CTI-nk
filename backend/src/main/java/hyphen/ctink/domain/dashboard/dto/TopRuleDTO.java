package hyphen.ctink.domain.dashboard.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.rule.enums.RuleType;

public record TopRuleDTO(
    AttackType attackType,
    RuleType ruleType,
    String ruleName,
    Long count
) {}
