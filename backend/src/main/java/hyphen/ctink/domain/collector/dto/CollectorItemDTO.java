package hyphen.ctink.domain.collector.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CollectorItemDTO(
        @JsonProperty("source_url") String sourceUrl,
        @JsonProperty("raw_content") String rawContent,
        @JsonProperty("git_diff") String gitDiff
) {}
