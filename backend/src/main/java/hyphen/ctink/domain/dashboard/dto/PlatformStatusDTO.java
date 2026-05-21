package hyphen.ctink.domain.dashboard.dto;

import hyphen.ctink.domain.cti.enums.CtiPlatform;
import hyphen.ctink.domain.platform.CollectionPlatform;

import java.time.LocalDateTime;

public record PlatformStatusDTO(
        Long platformId,
        CtiPlatform name,
        LocalDateTime lastCollectedAt
) {
    public static PlatformStatusDTO from(CollectionPlatform p) {
        return new PlatformStatusDTO(
                p.getId(),
                p.getName(),
                p.getLastCollectedAt()
        );
    }
}
