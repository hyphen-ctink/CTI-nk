package hyphen.ctink.domain.rule.dto;

import java.util.List;

public record DetectionRuleResponseDTO(
        Long totalCount,
        Long totalPages,
        Long currentPage,
        List<DetectionRuleDTO> detectionRule
) {}
