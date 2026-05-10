package hyphen.ctink.domain.log.notification.dto;

import java.util.List;

public record OtherNotificationResponseDTO(
        Long totalCount,
        Long totalPage,
        Long currentPage,
        List<OtherNotificationLogDTO> notifications
) {}
