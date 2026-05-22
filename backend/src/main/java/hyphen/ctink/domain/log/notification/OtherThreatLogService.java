package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.cti.OtherThreatRepository;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OtherThreatLogService {

    private final OtherThreatRepository otherThreatRepository;

    public void otherThreatLog() {
        long count = otherThreatRepository.count();

        if (count >= 20) {
            NotificationLog.builder()
                    .notificationType(NotificationType.OTHER_THREAT_ALERT)
                    .isSent(false)
                    .build();
        }
    }
}
