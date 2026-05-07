package hyphen.ctink.domain.user.dto;

public record LoginRequestDTO(
        String loginId,
        String password
) {}
