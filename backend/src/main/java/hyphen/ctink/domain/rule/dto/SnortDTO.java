package hyphen.ctink.domain.rule.dto;

public record SnortDTO(
        Long ruleId,
        String ruleName,
        String ruleContent
) {}
