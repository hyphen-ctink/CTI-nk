package hyphen.ctink.domain.log.ids.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;

import java.time.Instant;
import java.time.LocalDateTime;

public record IdsDetectionResultDTO(
    String ruleContent,
    String detail,
    Result result,
    Instant detectedAt
) {}
