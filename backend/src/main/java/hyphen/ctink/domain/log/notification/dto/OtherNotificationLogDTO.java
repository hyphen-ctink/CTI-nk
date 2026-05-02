package hyphen.ctink.domain.log.notification.dto;

import java.time.LocalDateTime;

public record OtherNotificationLogDTO(
        Long notificationId,
        String suspectedType,
        LocalDateTime createdAt
) {}
