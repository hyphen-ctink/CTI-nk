package hyphen.ctink.domain.log.ids.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;

import java.time.LocalDateTime;

public record IdsLogSearchConditionDTO(
    AttackType attackType,
    Result result,
    LocalDateTime dateFrom,
    LocalDateTime dateTo
) {}
