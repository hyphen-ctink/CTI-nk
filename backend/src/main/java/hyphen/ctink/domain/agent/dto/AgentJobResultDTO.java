package hyphen.ctink.domain.agent.dto;

import hyphen.ctink.domain.cti.entity.AttackDetail;
import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.IocType;
import hyphen.ctink.domain.rule.enums.RuleType;
import org.springframework.lang.Nullable;

import java.util.List;

public record AgentJobResultDTO(
        Long ctiDataId,
        String status,
        @Nullable AttackType attackType,
        @Nullable String attackDetail,
        @Nullable String summary,
        @Nullable DetectionRuleDTO detectionRule,
        @Nullable FeedbackDTO feedback,
        @Nullable Long regenCount
) {
    public record AttackDetailDTO(
            AttackType attackType,
            String detail
    ) {}

    public record DetectionRuleDTO(
            RuleType ruleType,
            IocType iocType,
            String iocValue,
            String ruleContent
    ) {}

    public record FeedbackDTO(
            String grammarResult,
            String grammarFeedback,
            String fnResult,
            String fnFeedback,
            String fpResult,
            String fpFeedback,
            String agentResult,
            String agentFeedback
    ) {}
}
