package hyphen.ctink.domain.agent.dto;

public record AgentJobDTO(
        Long ctiDataId,
        Long sid,
        Long platformId,
        String rawContent
) {}
