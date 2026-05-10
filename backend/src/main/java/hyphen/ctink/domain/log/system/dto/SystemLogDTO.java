package hyphen.ctink.domain.log.system.dto;

import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;

import java.time.LocalDateTime;

public record SystemLogDTO(
    Long logId,
    Stage stage,
    LogStatus status,
    String message,
    Long ctiId,
    Long ruleId,
    LocalDateTime createdAt
) {}
