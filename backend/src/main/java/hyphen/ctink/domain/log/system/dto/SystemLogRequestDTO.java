package hyphen.ctink.domain.log.system.dto;

import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;

public record SystemLogRequestDTO(
    Integer page,
    Stage stage,
    LogStatus status,
    String dateFrom,
    String dateTo
) {}
