package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.cti.OtherThreatRepository;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class OtherThreatLogService {

    private final OtherThreatRepository otherThreatRepository;
    private final NotificationLogRepository notificationLogRepository;

    @Transactional
    public void otherThreatLog() {
        long count = otherThreatRepository.count();

        if (count >= 20) {
            NotificationLog log = NotificationLog.builder()
                    .notificationType(NotificationType.OTHER_THREAT_ALERT)
                    .isSent(false)
                    .build();

            notificationLogRepository.save(log);
        }
    }
}
