package hyphen.ctink.domain.dashboard.dto;

import hyphen.ctink.domain.cti.entity.CtiData;

import java.time.LocalDateTime;

public record RecentThreatDTO(Long ctiId, String title, String attackType,
                              String processStatus, LocalDateTime collectedAt) {
    public static RecentThreatDTO from(CtiData entity) {
        return new RecentThreatDTO(
                entity.getId(),
                entity.getSummaryTitle(),
                entity.getAttackType().name().toLowerCase(),
                entity.getProcessStatus().name().toLowerCase(),
                entity.getCollectedAt()
        );
    }
}
