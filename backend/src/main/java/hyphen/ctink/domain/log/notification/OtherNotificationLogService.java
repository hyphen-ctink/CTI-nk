package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.log.notification.dto.OtherNotificationLogDTO;
import hyphen.ctink.domain.log.notification.dto.OtherNotificationResponseDTO;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OtherNotificationLogService {
    private final NotificationLogRepository notificationLogRepository;
    public OtherNotificationResponseDTO getOtherNotificationLog(Integer reqPage) {
        int page = (reqPage == null ? 1 : reqPage);

        Pageable pageable = PageRequest.of(
                page - 1,
                10,
                Sort.by("createdAt").descending()
        );

        Page<NotificationLog> queryResult = notificationLogRepository.findByNotificationType(
                NotificationType.OTHER_THREAT_ALERT, pageable
        );
        Page<OtherNotificationLogDTO> result = queryResult.map(notificationLog ->
                new OtherNotificationLogDTO(
                        notificationLog.getId(),
                        notificationLog.getSuspectedType(),
                        notificationLog.getCreatedAt()
                )
        );

        return new OtherNotificationResponseDTO(
                result.getTotalElements(),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );


    }
}
