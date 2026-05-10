package hyphen.ctink.domain.log.system;

import hyphen.ctink.domain.log.system.dto.SystemLogSearchConditionDTO;
import hyphen.ctink.domain.log.system.dto.SystemLogDTO;
import hyphen.ctink.domain.log.system.dto.SystemLogRequestDTO;
import hyphen.ctink.domain.log.system.dto.SystemLogResponseDTO;
import hyphen.ctink.domain.log.system.entity.SystemLog;
import hyphen.ctink.domain.log.system.enums.LogStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SystemLogService {
    private final SystemLogQueryRepository systemLogQueryRepository;
    private final SystemLogRepository systemLogRepository;

    public SystemLogResponseDTO getSystemLog(SystemLogRequestDTO req) {
        int page = (req.page() == null ? 1 : req.page());

        Pageable pageable = PageRequest.of(
                page - 1,
                15,
                Sort.by("createdAt").descending()
        );

        SystemLogSearchConditionDTO condition = new SystemLogSearchConditionDTO(
                req.stage(),
                req.status(),
                req.dateFrom() != null ? LocalDateTime.parse(req.dateFrom()) : null,
                req.dateTo() != null ? LocalDateTime.parse(req.dateTo()) : null
       );

        Page<SystemLog> queryResult = systemLogQueryRepository.search(condition, pageable);
        Page<SystemLogDTO> result = queryResult.map(systemLog ->
                new SystemLogDTO(
                        systemLog.getId(),
                        systemLog.getStage(),
                        systemLog.getLogStatus(),
                        systemLog.getMessage(),
                        systemLog.getCtiData() != null ? systemLog.getCtiData().getId() : null,
                        systemLog.getDetectionRule() != null ? systemLog.getDetectionRule().getId() : null,
                        systemLog.getCreatedAt()
                )
        );

        return new SystemLogResponseDTO(
                result.getTotalElements(),
                systemLogRepository.countByLogStatus(LogStatus.SUCCESS),
                systemLogRepository.countByLogStatus(LogStatus.FAILURE),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );
    }
}
