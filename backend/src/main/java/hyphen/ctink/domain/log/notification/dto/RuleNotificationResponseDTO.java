package hyphen.ctink.domain.log.notification.dto;

import java.util.List;

public record RuleNotificationResponseDTO(
        Long totalCount,
        Long totalPages,
        Long currentPage,
        List<RuleNotificationLogDTO> rules
) {}
