package hyphen.ctink.domain.admin.dto;

import java.time.LocalDateTime;

public record PendingUsersDTO(
        String userId,
        String name,
        String organization,
        String position,
        String email,
        String phone,
        LocalDateTime createdAt
) {}
