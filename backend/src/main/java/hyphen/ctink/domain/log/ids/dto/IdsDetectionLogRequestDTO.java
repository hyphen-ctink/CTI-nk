package hyphen.ctink.domain.log.ids.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;

public record IdsDetectionLogRequestDTO(
        Integer page,
        AttackType attackType,
        Result result,
        String dateFrom,
        String dateTo
) {}
