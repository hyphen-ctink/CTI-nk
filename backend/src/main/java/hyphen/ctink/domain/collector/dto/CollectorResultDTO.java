package hyphen.ctink.domain.collector.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.time.LocalDateTime;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CollectorResultDTO(
    @JsonProperty("platform_id") Long platformId,
    String status,
    @JsonProperty("last_commit_sha") String lastCommitSha,
    @JsonProperty("collected_at") LocalDateTime collectedAt,
    CollectorItemDTO item
) {}
