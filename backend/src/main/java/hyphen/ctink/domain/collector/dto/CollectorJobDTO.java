package hyphen.ctink.domain.collector.dto;

import java.time.LocalDateTime;

public record CollectorJobDTO(
        String jobId,
        Long platformId,
        String lastCommitSha,
        LocalDateTime lastCollectedAt
) {}
