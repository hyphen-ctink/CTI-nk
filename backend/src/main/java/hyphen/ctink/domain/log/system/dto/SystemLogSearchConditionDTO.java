package hyphen.ctink.domain.log.system.dto;

import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;

import java.time.LocalDateTime;

public record SystemLogSearchConditionDTO(
       Stage stage,
       LogStatus status,
       LocalDateTime dateFrom,
       LocalDateTime dateTo
) {}
