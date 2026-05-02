package hyphen.ctink.domain.log.ids.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;

import java.time.LocalDateTime;

public record IdsDetectionLogDTO(
    Long logId,
    Long ruleId,
    String ruleName,
    AttackType attackType,
    Result result,
    LocalDateTime detectedAt
) {}
