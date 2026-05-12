package hyphen.ctink.domain.indicator.dto;

public record UpdateTrustLevelJobResultDTO(
        String ioc,
        String status,
        String platform,
        Boolean result
) {}
