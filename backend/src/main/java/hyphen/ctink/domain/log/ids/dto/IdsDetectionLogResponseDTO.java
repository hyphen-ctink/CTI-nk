package hyphen.ctink.domain.log.ids.dto;

import java.util.List;

public record IdsDetectionLogResponseDTO(
        Long totalCount,
        Long alertCount,
        Long blockedCount,
        Long detectedCount,
        Long totalPages,
        Long currentPage,
        List<IdsDetectionLogDTO> logs
) {}
