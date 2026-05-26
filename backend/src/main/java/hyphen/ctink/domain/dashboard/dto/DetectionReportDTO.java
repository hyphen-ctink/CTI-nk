package hyphen.ctink.domain.dashboard.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.enums.RuleType;

import java.time.LocalDate;
import java.util.List;

public record DetectionReportDTO(
        LocalDate thisWeekFrom,
        LocalDate thisWeekTo,
        LocalDate lastWeekFrom,
        LocalDate lastWeekTo,
        List<RuleTypeResult> byRuleTypeResult,
        List<AttackTypeResult> byAttackType,
        List<TopRulesByAttackType> topRulesByAttackType,
        List<Date> byDate,
        List<Date> prevByDate,
        List<TopRulesByRuleType> topRulesByRuleType,
        List<CountByTrustLevel> ByTrustLevel

) {
    public record RuleTypeResult(
            RuleType ruleType,
            Long alertCount,
            Long detectedCount,
            Long blockedCount,
            Long prevAlertCount,
            Long prevDetectedCount,
            Long prevBlockedCount
    ) {}

    public record AttackTypeResult(
            AttackType attackType,
            Long count,
            Long prevCount
    ) {}

    public record TopRulesByAttackType(
            AttackType attackType,
            List<Rules1> rules
    ) {}
    public record Rules1(
            RuleType ruleType,
            String ruleName,
            Long count
    ) {}

    public record TopRulesByRuleType(
            RuleType ruleType,
            List<Rules2> rules
    ) {}
    public record Rules2(
            AttackType attackType,
            String ruleName,
            Long count
    ) {}

    public record Date(
            LocalDate date,
            Long count
    ) {}

    public record CountByTrustLevel(
            TrustLevel trustLevel,
            Long count,
            Long prevCount
    ) {}
}
