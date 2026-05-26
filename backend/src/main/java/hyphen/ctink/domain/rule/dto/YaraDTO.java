package hyphen.ctink.domain.rule.dto;

public record YaraDTO(
    Long ruleId,
    String ruleName,
    String ruleContent
) {}
