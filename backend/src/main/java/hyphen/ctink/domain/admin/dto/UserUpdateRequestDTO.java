package hyphen.ctink.domain.admin.dto;

import hyphen.ctink.domain.user.enums.Role;
import hyphen.ctink.domain.user.enums.UserStatus;
import org.springframework.lang.Nullable;

public record UserUpdateRequestDTO(
        @Nullable Role role,
        @Nullable UserStatus status
) {}
