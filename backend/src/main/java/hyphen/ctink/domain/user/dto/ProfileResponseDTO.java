package hyphen.ctink.domain.user.dto;

import hyphen.ctink.domain.user.enums.UserStatus;

import java.time.LocalDateTime;

public record ProfileResponseDTO(
        String loginId,
        String name,
        String organization,
        String position,
        String email,
        String phone,
        UserStatus status,
        LocalDateTime lastLoginAt
) {}
