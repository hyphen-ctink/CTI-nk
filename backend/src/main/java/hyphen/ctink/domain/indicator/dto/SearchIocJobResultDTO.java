package hyphen.ctink.domain.indicator.dto;

public record SearchIocJobResultDTO(
        String ioc,
        String status,
        String platform,
        Boolean result
) {}
