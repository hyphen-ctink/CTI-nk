package hyphen.ctink.domain.admin.dto;

import hyphen.ctink.domain.user.enums.Role;
import hyphen.ctink.domain.user.enums.UserStatus;

import java.time.LocalDateTime;

public record UsersDTO(
        String userId,
        String name,
        String organization,
        String position,
        String email,
        String phone,
        Role role,
        UserStatus status,
        LocalDateTime lastLoginAt
) {}
