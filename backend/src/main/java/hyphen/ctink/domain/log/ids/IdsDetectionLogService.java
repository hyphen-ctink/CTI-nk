package hyphen.ctink.domain.log.ids;

import hyphen.ctink.domain.log.ids.dto.IdsDetectionLogDTO;
import hyphen.ctink.domain.log.ids.dto.IdsDetectionLogRequestDTO;
import hyphen.ctink.domain.log.ids.dto.IdsDetectionLogResponseDTO;
import hyphen.ctink.domain.log.ids.dto.IdsLogSearchConditionDTO;
import hyphen.ctink.domain.log.ids.entity.IdsDetectionLog;
import hyphen.ctink.domain.log.ids.enums.Result;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class IdsDetectionLogService {
    private final IdsDetectionLogQueryRepository idsDetectionLogQueryRepository;
    private final IdsDetectionLogRepository idsDetectionLogRepository;

    public IdsDetectionLogResponseDTO getIdsDetectionLog(IdsDetectionLogRequestDTO req) {
        int page = (req.page() == null ? 1 : req.page());

        Pageable pageable = PageRequest.of(
                page - 1,
                15,
                Sort.by("detectedAt").descending()
        );

        IdsLogSearchConditionDTO condition = new IdsLogSearchConditionDTO(
                req.attackType(),
                req.result(),
                req.dateFrom() != null ? LocalDateTime.parse(req.dateFrom()) : null,
                req.dateTo() != null ? LocalDateTime.parse(req.dateTo()) : null
        );

        Page<IdsDetectionLog> queryResult = idsDetectionLogQueryRepository.search(condition, pageable);
        Page<IdsDetectionLogDTO> result = queryResult.map(idsDetectionLog ->
                new IdsDetectionLogDTO(
                        idsDetectionLog.getId(),
                        idsDetectionLog.getDetectionRule() != null ? idsDetectionLog.getDetectionRule().getId() : null,
                        idsDetectionLog.getDetectionRule() != null ? idsDetectionLog.getDetectionRule().getRuleName() : null,
                        idsDetectionLog.getAttackType(),
                        idsDetectionLog.getResult(),
                        idsDetectionLog.getDetectedAt()
                )
        );

        return new IdsDetectionLogResponseDTO(
                result.getTotalElements(),
                idsDetectionLogRepository.countByResult(Result.ALERT),
                idsDetectionLogRepository.countByResult(Result.BLOCK),
                idsDetectionLogRepository.countByResult(Result.DETECT),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );
    }
}
