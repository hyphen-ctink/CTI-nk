package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.log.notification.dto.RuleNotificationLogDTO;
import hyphen.ctink.domain.log.notification.dto.RuleNotificationRequestDTO;
import hyphen.ctink.domain.log.notification.dto.RuleNotificationResponseDTO;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RuleNotificationLogService {
    private final RuleNotificationLogQueryRepository ruleNotificationLogQueryRepository;

    public RuleNotificationResponseDTO getRuleNotificationLog(RuleNotificationRequestDTO req) {
        int page = (req.page() == null ? 1 : req.page());

        Pageable pageable = PageRequest.of(
                page - 1,
                5,
                Sort.by("createdAt").descending()
        );

        Page<NotificationLog> queryResult = ruleNotificationLogQueryRepository.search(req.ruleType(), pageable);
        Page<RuleNotificationLogDTO> result = queryResult.map(notificationLog ->
                new RuleNotificationLogDTO(
                        notificationLog.getDetectionRule() != null ? notificationLog.getDetectionRule().getId() : null,
                        notificationLog.getDetectionRule() != null ? notificationLog.getDetectionRule().getRuleName() : null,
                        notificationLog.getRuleType(),
                        notificationLog.getDetectionRule() != null ? notificationLog.getDetectionRule().getAttackType() : null,
                        notificationLog.getDetectionRule() != null ? notificationLog.getDetectionRule().getTrustLevel() : null,
                        notificationLog.getCreatedAt()
                )
        );

        return new RuleNotificationResponseDTO(
                result.getTotalElements(),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );
    }
}
