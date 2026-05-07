package hyphen.ctink.domain.user.dto;

import hyphen.ctink.domain.user.enums.Role;
import org.springframework.lang.Nullable;

public record LoginResponseDTO(
        @Nullable String message,
        @Nullable Role role,
        @Nullable String name,
        @Nullable Integer loginAttempts
) {}
