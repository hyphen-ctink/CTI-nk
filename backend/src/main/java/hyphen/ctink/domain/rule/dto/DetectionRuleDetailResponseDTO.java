package hyphen.ctink.domain.rule.dto;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.IocDTO;
import hyphen.ctink.domain.indicator.enums.TrustLevel;

import java.util.List;

public record DetectionRuleDetailResponseDTO(
        Long ctiId,
        String sourceUrl,
        AttackType attackType,
        List<IocDTO> iocList,
        TrustLevel trustLevel,
        DetectionRuleDetailDTO targetRule,
        List<SnortDTO> snortRules,
        List<YaraDTO> yaraRules
) {}
