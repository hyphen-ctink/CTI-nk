package hyphen.ctink.domain.rule.dto;

import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;

import java.time.LocalDateTime;

public record DetectionRuleDetailDTO(
        Long ruleId,
        String ruleName,
        RuleType ruleType,
        RuleStatus status,
        String ruleContent,
        String grammarResult,
        String fnResult,
        String fpResult,
        String agentJudgement,
        Long regenCount,
        LocalDateTime createdAt
) {}
