package hyphen.ctink.domain.rule.dto;

import hyphen.ctink.domain.rule.enums.OsType;

public record YaraDTO(
    Long ruleId,
    String ruleName,
    OsType osType,
    String ruleContent
) {}
