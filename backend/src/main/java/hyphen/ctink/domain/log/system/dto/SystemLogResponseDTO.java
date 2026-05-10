package hyphen.ctink.domain.log.system.dto;

import java.util.List;

public record SystemLogResponseDTO(
    Long totalCount,
    Long successCount,
    Long failureCount,
    Long totalPages,
    Long currentPage,
    List<SystemLogDTO> logs
) {}