package hyphen.ctink.domain.dashboard.dto;

import hyphen.ctink.domain.cti.enums.AttackType;

public record AttackTypeDistributionDTO(
        AttackType attackType, Long count
) {}
