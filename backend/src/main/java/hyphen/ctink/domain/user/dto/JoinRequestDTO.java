package hyphen.ctink.domain.user.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

public record JoinRequestDTO(
    String loginId,
    String password,
    String name,
    String organization,
    String position,
    String email,
    String phone
) {}
